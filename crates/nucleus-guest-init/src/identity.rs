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
/// The pod's own UUID, read out of the SPIFFE ID the host just served it.
///
/// # Why this exists, and why it is not an environment variable from the host
///
/// The tool-proxy reads `NUCLEUS_POD_ID` to decide whether a pod-scoped lockdown
/// command is aimed at it (`lockdown_client::apply_scope`). Nothing in the tree
/// ever set that variable — so the `Some(my_id) => my_id == target_pod` branch was
/// unreachable, and `apply_scope` fell to its `None => true` case: a lockdown
/// aimed at ONE pod locked down EVERY pod on the node. Fail-safe, and silently
/// non-functional as a targeting mechanism.
///
/// The identity is taken from the SVID rather than injected by the host as an
/// env var because the SVID arrives over the per-pod vsock socket that the host
/// creates per VM — the guest cannot forge which socket it is connected to,
/// whereas any value merely placed in the environment is only as good as
/// everything that can write to the environment. This is the same reasoning that
/// makes the workload API's `pod_id` trustworthy host-side: the identifier comes
/// from the transport, not from the payload.
///
/// Returns `None` rather than guessing when the ID is not the expected shape —
/// a wrong pod id is worse than no pod id, because `apply_scope`'s `None` branch
/// is the safe one.
#[must_use]
pub fn pod_id_from_spiffe(spiffe_id: &str) -> Option<String> {
    // `spiffe://{trust_domain}/ns/pods/sa/{pod_id}` — see
    // nucleus_node::workload_api_vsock, which mints exactly this form.
    let rest = spiffe_id.strip_prefix("spiffe://")?;
    let (_trust_domain, path) = rest.split_once('/')?;
    let id = path.strip_prefix("ns/pods/sa/")?;
    if id.is_empty() || id.contains('/') {
        return None;
    }
    Some(id.to_string())
}

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

#[cfg(test)]
mod pod_id_tests {
    use super::pod_id_from_spiffe;

    /// The form `nucleus_node::workload_api_vsock` actually mints.
    #[test]
    fn the_pod_uuid_is_read_from_the_workload_api_form() {
        assert_eq!(
            pod_id_from_spiffe(
                "spiffe://nucleus.local/ns/pods/sa/d6bf354e-6d41-42fe-8aa8-8c287a8db798"
            )
            .as_deref(),
            Some("d6bf354e-6d41-42fe-8aa8-8c287a8db798")
        );
    }

    /// The OTHER SPIFFE form a pod has — `ns/{namespace}/sa/{metadata.name}`,
    /// which the node registers for the broker — is NOT a pod id and must not be
    /// mistaken for one. Two pods can share a `metadata.name`; a pod UUID is
    /// unique. Returning that string here would make lockdown scoping match the
    /// wrong set of pods.
    #[test]
    fn the_namespace_form_is_not_mistaken_for_a_pod_id() {
        assert_eq!(
            pod_id_from_spiffe("spiffe://nucleus.local/ns/default/sa/my-agent"),
            None
        );
    }

    /// STRUCTURAL: the parser being correct proves nothing if nobody calls it.
    /// The whole defect was a consumer (`apply_scope`) reading a variable no
    /// producer ever set, and this test is what would have caught that. It reads
    /// main.rs and fails if the identity branch stops setting NUCLEUS_POD_ID.
    #[test]
    fn guest_init_still_sets_the_pod_id_after_fetching_identity() {
        let src = include_str!("main.rs");
        assert!(
            src.contains("pod_id_from_spiffe"),
            "guest-init no longer derives the pod id from the SVID — pod-scoped \
             lockdown silently reverts to locking every pod on the node"
        );
        assert!(
            src.contains("NUCLEUS_POD_ID"),
            "guest-init no longer sets NUCLEUS_POD_ID — the variable the \
             tool-proxy reads would have no producer again"
        );
    }

    /// Malformed input yields None rather than a guess: `apply_scope`'s None
    /// branch is the conservative one, so refusing to parse fails safe.
    #[test]
    fn malformed_ids_yield_none_rather_than_a_guess() {
        for bad in [
            "",
            "not-a-spiffe-id",
            "spiffe://nucleus.local",
            "spiffe://nucleus.local/ns/pods/sa/",
            "spiffe://nucleus.local/ns/pods/sa/a/b",
        ] {
            assert_eq!(pod_id_from_spiffe(bad), None, "should not parse: {bad}");
        }
    }
}
