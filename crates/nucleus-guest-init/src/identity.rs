//! SPIFFE identity fetching via vsock.
//!
//! This module handles fetching X.509 SVID certificates from the host's
//! Workload API over a vsock connection.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use vsock::VsockStream;

/// Default vsock port for the Workload API.
#[allow(dead_code)]
pub const DEFAULT_WORKLOAD_API_PORT: u32 = 15012;

/// Host CID for vsock connections (always 2 in Firecracker).
const VMADDR_CID_HOST: u32 = 2;

/// Directory to store identity files.
const IDENTITY_DIR: &str = "/etc/nucleus/identity";

/// Response from FETCH_SVID command.
#[derive(Debug, serde::Deserialize)]
struct SvidResponse {
    spiffe_id: String,
    certificate_chain: String,
    private_key: String,
    #[allow(dead_code)]
    expires_at: i64,
}

/// Response from FETCH_BUNDLE command.
#[derive(Debug, serde::Deserialize)]
struct BundleResponse {
    #[allow(dead_code)]
    trust_domain: String,
    bundle_pem: String,
}

/// Where [`fetch_identity`] writes the SVID certificate chain.
///
/// Exposed so the caller can advertise it to the tool-proxy via
/// `NUCLEUS_IDENTITY_CERT`. Fetching the cert and not naming it leaves Tier 1/2
/// reporting "no identity cert" with the cert sitting on disk.
pub fn svid_cert_path() -> String {
    format!("{IDENTITY_DIR}/svid.pem")
}

/// The three values a session capability token comprises.
///
/// Named to match what the tool-proxy reads from its environment —
/// `NUCLEUS_TASK_TOKEN{,_NONCE,_ISSUER}` — because a mismatch here fails at
/// proxy startup rather than at use, which is far from the cause.
#[derive(Debug, serde::Deserialize)]
pub struct TaskTokenResponse {
    pub token: String,
    pub nonce: String,
    pub issuer: String,
}

/// Fetch this pod's session capability token from the host.
///
/// # Why over vsock rather than the kernel command line
///
/// The token rides `nucleus.task_token_hex`/`_nonce`/`_issuer` today. It is not
/// a secret — a scoped capability plus a public issuer key — so this is not
/// about confidentiality. It is that **per-pod material baked into a boot
/// artifact survives a snapshot**: every clone restored from one base would
/// carry a single pod's token. Fetching after boot is what makes a snapshot base
/// reusable, and three of the five keys blocking one are these.
///
/// Fetched synchronously here, before the tool-proxy is exec'd, so the values
/// are in the environment before anything reads them. That ordering is the whole
/// risk of moving delivery off the command line, and it is structural rather
/// than hoped-for: `main` calls this and only then calls `exec_proxy`.
/// This pod's DLC-D verified-admission provisioning, from `FETCH_DLC_ADMISSION`.
#[derive(serde::Deserialize)]
pub struct DlcAdmissionResponse {
    /// Comma-separated hex trusted issuer public keys.
    pub trusted_keys: String,
    /// Hex public key of the issuer whose credentials this pod presents.
    pub issuer: String,
    /// Comma-separated `operation=hex_signature` credentials.
    pub credentials: String,
}

/// Fetch this pod's DLC admission provisioning from the host. `Ok(None)` is the
/// ordinary unprovisioned case (the host answers `{"error": ...}`); only a
/// transport failure is an `Err`.
pub fn fetch_dlc_admission(port: u32) -> Result<Option<DlcAdmissionResponse>, String> {
    let mut stream = VsockStream::connect_with_cid_port(VMADDR_CID_HOST, port)
        .map_err(|e| format!("failed to connect to workload API: {e}"))?;
    stream
        .write_all(b"FETCH_DLC_ADMISSION\n")
        .map_err(|e| format!("failed to send FETCH_DLC_ADMISSION: {e}"))?;
    stream
        .flush()
        .map_err(|e| format!("failed to flush: {e}"))?;

    let mut reader = BufReader::new(&mut stream);
    let mut response = String::new();
    reader
        .read_line(&mut response)
        .map_err(|e| format!("failed to read dlc admission response: {e}"))?;

    match serde_json::from_str::<DlcAdmissionResponse>(&response) {
        Ok(material) => Ok(Some(material)),
        // The unprovisioned host answers {"error": ...}: not a failure.
        Err(_) => Ok(None),
    }
}

/// Fetch this pod's credential-broker capability, once.
///
/// # Why this must happen before `exec_proxy`
///
/// The host serves this secret EXACTLY ONCE per pod. That one-shot is the whole
/// security property: any guest process can open `AF_VSOCK` — permissions on
/// `/dev/vsock` do not gate the socket family, which was verified by experiment
/// — so a workload can reach the workload API too. What it cannot do is arrive
/// first. Fetching here, before the proxy execs and long before it spawns any
/// workload, is what makes "first" true.
///
/// # And why the value must not be logged
///
/// Possession of this IS the capability to speak to the credential broker as the
/// mediating proxy. Unlike the task token (a scoped capability plus a public
/// issuer key) there is no sense in which handing it out is harmless, so errors
/// here name the failure and never the payload.
pub struct BrokerCapability {
    /// The HMAC key the proxy signs broker frames with.
    pub secret: String,
    /// The vsock port the broker listens on.
    pub port: u32,
}

pub fn fetch_broker_secret(port: u32) -> Result<BrokerCapability, String> {
    let mut stream = VsockStream::connect_with_cid_port(VMADDR_CID_HOST, port)
        .map_err(|e| format!("failed to connect to workload API: {e}"))?;
    stream
        .write_all(b"FETCH_BROKER_SECRET\n")
        .map_err(|e| format!("failed to send FETCH_BROKER_SECRET: {e}"))?;
    stream
        .flush()
        .map_err(|e| format!("failed to flush: {e}"))?;

    let mut reader = BufReader::new(&mut stream);
    let mut response = String::new();
    reader
        .read_line(&mut response)
        .map_err(|e| format!("failed to read broker-secret response: {e}"))?;

    let parsed: serde_json::Value = serde_json::from_str(&response)
        // Not `{e}` and not the body: a parse error that echoed the response
        // would put the capability in the guest console log.
        .map_err(|_| "broker-secret response was not valid JSON".to_string())?;
    if let Some(err) = parsed.get("error").and_then(|e| e.as_str()) {
        return Err(err.to_string());
    }
    let secret = parsed
        .get("secret")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| "broker-secret response had no `secret`".to_string())?;
    // Both or neither. A secret with no port leaves the proxy able to sign and
    // unable to connect — a capability that looks held and is not, which is the
    // failure shape this whole arc keeps producing.
    let broker_port = parsed
        .get("port")
        .and_then(serde_json::Value::as_u64)
        .and_then(|p| u32::try_from(p).ok())
        .filter(|p| *p != 0)
        .ok_or_else(|| "broker-secret response had no usable `port`".to_string())?;
    Ok(BrokerCapability {
        secret,
        port: broker_port,
    })
}

/// The S3 audit-sink credentials, fetched over the workload API instead of
/// read off the world-readable kernel command line.
pub struct AuditCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    /// Present only for temporary (STS) credentials.
    pub session_token: Option<String>,
}

/// Fetch the S3 audit-sink credentials, once.
///
/// Same discipline as [`fetch_broker_secret`], for the same reason: the host
/// serves these EXACTLY ONCE, and fetching before `exec_proxy` — before any
/// workload exists — is what makes "first" mean "the proxy". These credentials
/// write the audit trail, so errors here name the failure and never echo the
/// response body (which would put cloud credentials in the guest console log).
///
/// `Ok(None)` when the pod has no audit sink — the ordinary case, not a
/// failure.
pub fn fetch_audit_credentials(port: u32) -> Result<Option<AuditCredentials>, String> {
    let mut stream = VsockStream::connect_with_cid_port(VMADDR_CID_HOST, port)
        .map_err(|e| format!("failed to connect to workload API: {e}"))?;
    stream
        .write_all(b"FETCH_AUDIT_CREDENTIALS\n")
        .map_err(|e| format!("failed to send FETCH_AUDIT_CREDENTIALS: {e}"))?;
    stream
        .flush()
        .map_err(|e| format!("failed to flush: {e}"))?;

    let mut reader = BufReader::new(&mut stream);
    let mut response = String::new();
    reader
        .read_line(&mut response)
        .map_err(|e| format!("failed to read audit-credentials response: {e}"))?;

    let parsed: serde_json::Value = serde_json::from_str(&response)
        // Not `{e}` and not the body: a parse error that echoed the response
        // would put the credentials in the guest console log.
        .map_err(|_| "audit-credentials response was not valid JSON".to_string())?;
    if let Some(err) = parsed.get("error").and_then(|e| e.as_str()) {
        // "not provisioned" is the unremarkable no-audit-sink case; every other
        // error (including "already served") is worth surfacing.
        if err.contains("no audit credentials provisioned") {
            return Ok(None);
        }
        return Err(err.to_string());
    }
    let access_key_id = parsed
        .get("access_key_id")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| "audit-credentials response had no `access_key_id`".to_string())?;
    let secret_access_key = parsed
        .get("secret_access_key")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| "audit-credentials response had no `secret_access_key`".to_string())?;
    let session_token = parsed
        .get("session_token")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    Ok(Some(AuditCredentials {
        access_key_id,
        secret_access_key,
        session_token,
    }))
}

/// Fetch this pod's caller-identity token for the node's management API.
///
/// Over the per-pod workload-API socket, like every other per-pod artifact: the
/// host serves the token belonging to whichever pod's socket this is, so the
/// guest never states which pod it wants a token for.
pub fn fetch_pod_caller_token(port: u32) -> Result<String, String> {
    let mut stream = VsockStream::connect_with_cid_port(VMADDR_CID_HOST, port)
        .map_err(|e| format!("failed to connect to workload API: {e}"))?;
    stream
        .write_all(b"FETCH_POD_CALLER_TOKEN\n")
        .map_err(|e| format!("failed to send FETCH_POD_CALLER_TOKEN: {e}"))?;
    stream
        .flush()
        .map_err(|e| format!("failed to flush: {e}"))?;

    let mut reader = BufReader::new(&mut stream);
    let mut response = String::new();
    reader
        .read_line(&mut response)
        .map_err(|e| format!("failed to read caller token: {e}"))?;

    let v: serde_json::Value = serde_json::from_str(&response)
        .map_err(|e| format!("caller token response is not JSON: {e}"))?;
    v.get("caller_token")
        .and_then(|t| t.as_str())
        .map(str::to_string)
        .ok_or_else(|| "no caller_token in response".to_string())
}

/// Fetch this pod's live-path session capability token.
///
/// `Ok(None)` when the host minted no token for this pod (a degraded but
/// legitimate state — the tool-proxy then records the token as Missing and
/// fails closed at verify). `Err` is reserved for a real transport or
/// protocol failure, which the caller treats as fatal on the identity path
/// where the kernel-cmdline fallback no longer exists.
pub fn fetch_task_token(port: u32) -> Result<Option<TaskTokenResponse>, String> {
    let mut stream = VsockStream::connect_with_cid_port(VMADDR_CID_HOST, port)
        .map_err(|e| format!("failed to connect to workload API: {e}"))?;
    stream
        .write_all(b"FETCH_TASK_TOKEN\n")
        .map_err(|e| format!("failed to send FETCH_TASK_TOKEN: {e}"))?;
    stream
        .flush()
        .map_err(|e| format!("failed to flush: {e}"))?;

    let mut reader = BufReader::new(&mut stream);
    let mut response = String::new();
    reader
        .read_line(&mut response)
        .map_err(|e| format!("failed to read task token response: {e}"))?;

    // The host answers a pod with no minted token with `{"error": ...}` rather
    // than an empty token — the ordinary degraded case, distinguished HERE from
    // a real protocol problem so the caller can make only the latter fatal.
    if let Ok(t) = serde_json::from_str::<TaskTokenResponse>(&response) {
        return Ok(Some(t));
    }
    let v: serde_json::Value = serde_json::from_str(&response).map_err(|e| {
        format!(
            "failed to parse task token response ({e}): {}",
            response.trim()
        )
    })?;
    if v.get("error").and_then(|e| e.as_str()).is_some() {
        // Explicit "no token minted" — not a failure.
        return Ok(None);
    }
    Err(format!(
        "task token response had neither a token nor an error: {}",
        response.trim()
    ))
}

/// Fetches the workload certificate from the host via vsock.
///
/// This connects to the host's Workload API server, fetches the X.509 SVID,
/// and writes the certificate and key to the identity directory.
///
/// Returns the SPIFFE ID on success.
pub fn fetch_identity(port: u32) -> Result<String, String> {
    // Create identity directory
    fs::create_dir_all(IDENTITY_DIR)
        .map_err(|e| format!("failed to create identity directory: {e}"))?;

    // Connect to host Workload API via vsock
    let mut stream = VsockStream::connect_with_cid_port(VMADDR_CID_HOST, port)
        .map_err(|e| format!("failed to connect to workload API: {e}"))?;

    // Fetch SVID
    let svid = fetch_svid(&mut stream)?;

    // Write certificate chain
    let cert_path = Path::new(IDENTITY_DIR).join("svid.pem");
    fs::write(&cert_path, &svid.certificate_chain)
        .map_err(|e| format!("failed to write certificate: {e}"))?;

    // Write private key with restricted permissions
    let key_path = Path::new(IDENTITY_DIR).join("svid.key");
    write_private_key(&key_path, &svid.private_key)?;

    // Fetch trust bundle
    let mut stream = VsockStream::connect_with_cid_port(VMADDR_CID_HOST, port)
        .map_err(|e| format!("failed to reconnect to workload API: {e}"))?;
    let bundle = fetch_bundle(&mut stream)?;

    // Write trust bundle
    let bundle_path = Path::new(IDENTITY_DIR).join("bundle.pem");
    fs::write(&bundle_path, &bundle.bundle_pem)
        .map_err(|e| format!("failed to write trust bundle: {e}"))?;

    Ok(svid.spiffe_id)
}

/// Fetches the X.509 SVID from the Workload API.
fn fetch_svid(stream: &mut VsockStream) -> Result<SvidResponse, String> {
    // Send FETCH_SVID command
    stream
        .write_all(b"FETCH_SVID\n")
        .map_err(|e| format!("failed to send FETCH_SVID: {e}"))?;
    stream
        .flush()
        .map_err(|e| format!("failed to flush: {e}"))?;

    // Read response
    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    reader
        .read_line(&mut response)
        .map_err(|e| format!("failed to read SVID response: {e}"))?;

    // Parse JSON response
    let svid: SvidResponse = serde_json::from_str(&response)
        .map_err(|e| format!("failed to parse SVID response: {e}"))?;

    if svid.spiffe_id.is_empty() {
        return Err("empty SPIFFE ID in response".to_string());
    }

    Ok(svid)
}

/// Fetches the trust bundle from the Workload API.
fn fetch_bundle(stream: &mut VsockStream) -> Result<BundleResponse, String> {
    // Send FETCH_BUNDLE command
    stream
        .write_all(b"FETCH_BUNDLE\n")
        .map_err(|e| format!("failed to send FETCH_BUNDLE: {e}"))?;
    stream
        .flush()
        .map_err(|e| format!("failed to flush: {e}"))?;

    // Read response
    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    reader
        .read_line(&mut response)
        .map_err(|e| format!("failed to read bundle response: {e}"))?;

    // Parse JSON response
    let bundle: BundleResponse = serde_json::from_str(&response)
        .map_err(|e| format!("failed to parse bundle response: {e}"))?;

    Ok(bundle)
}

/// Writes a private key file with restricted permissions (0600).
fn write_private_key(path: &Path, content: &str) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("failed to create key file: {e}"))?;
        file.write_all(content.as_bytes())
            .map_err(|e| format!("failed to write key: {e}"))?;
    }

    #[cfg(not(target_os = "linux"))]
    {
        fs::write(path, content).map_err(|e| format!("failed to write key: {e}"))?;
    }

    Ok(())
}

/// Parses the workload API port from kernel command line.
///
/// Looks for `nucleus.workload_api_port=<port>` in the cmdline.
pub fn parse_workload_api_port(cmdline: &str) -> Option<u32> {
    for token in cmdline.split_whitespace() {
        if let Some(value) = token.strip_prefix("nucleus.workload_api_port=") {
            return value.parse().ok();
        }
    }
    None
}

/// Returns true if identity should be fetched (port is configured).
#[allow(dead_code)]
pub fn should_fetch_identity(cmdline: &str) -> bool {
    parse_workload_api_port(cmdline).is_some()
}
