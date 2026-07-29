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
pub fn fetch_task_token(port: u32) -> Result<TaskTokenResponse, String> {
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
    // than an empty token, so a parse failure here is a real protocol problem
    // and not the ordinary "this pod has none" case.
    serde_json::from_str::<TaskTokenResponse>(&response).map_err(|e| {
        format!(
            "failed to parse task token response ({e}): {}",
            response.trim()
        )
    })
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
