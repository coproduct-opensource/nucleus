//! The transport `nucleus run --local` and `nucleus shell` give the tool-proxy
//! they spawn (#2446 step 2).
//!
//! Both used to bind the proxy on loopback TCP and hand it, and the agent's own
//! MCP bridge, an auth secret and an approval secret. The auth secret signed
//! for the shared-secret tier, whose authority ceiling is now zero: the proxy
//! admits only `/v1/health` on it. The approval secret let the agent's bridge
//! sign approvals for the agent.
//!
//! Now the proxy listens on its peer-verified Unix socket, and the bridge
//! reaches it there with no credential at all: the proxy admits it by its
//! kernel-reported uid. The proxy still needs an approval authority to start,
//! so it is given the PUBLIC half of a key this process generates and drops.
//! No one on this host tier can approve an operation the policy holds for
//! approval; it is refused with its reason, which the bridge relays.
//!
//! The proxy's sandbox proof (#2446 step 3a) is an identity minted for the
//! run: an SVID naming the run, its key and the root that issued it, written
//! into the run directory by `nucleus_identity::pod_files`, the declaration
//! nucleus-node's local driver writes from. The proxy reads it as tier 2. It
//! replaced tier 3, an orchestrator token HMAC'd with a secret this process
//! made up and passed as `--auth-secret`, on an argv any local user can read,
//! for no other purpose than that one check.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use nucleus_identity::pod_files::{self, PodIdentityFiles};
use uuid::Uuid;

/// The socket's name in the run directory.
const SOCKET_FILE: &str = "p.sock";

/// A run directory short enough for the socket inside it. A Unix socket path is
/// limited to 104 bytes on macOS, where the temp dir alone can be ~50, so the
/// directory takes 12 hex characters of the run id rather than all 36.
pub(crate) fn run_dir(prefix: &str, run_id: &Uuid) -> PathBuf {
    let short = &run_id.simple().to_string()[..12];
    std::env::temp_dir().join(format!("{prefix}-{short}"))
}

/// How long the run's identity is valid. The proxy checks it once, when it
/// starts; a day outlasts any run and any `shell --print-config` session.
const IDENTITY_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// The proxy's listener, approval authority and sandbox proof for a run in
/// `run_dir`.
pub(crate) struct LocalProxyTransport {
    socket: PathBuf,
    approval_pubkey_hex: String,
    identity: PodIdentityFiles,
}

impl LocalProxyTransport {
    /// Mints the run's identity into `run_dir`, which must exist.
    pub(crate) fn new(run_dir: &Path, run_id: &Uuid) -> Result<Self> {
        // Generated and dropped: only its public half leaves this function.
        let approver = ed25519_dalek::SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let identity = pod_files::issue_ephemeral(run_dir, &run_id.to_string(), IDENTITY_TTL)
            .context("minting the tool-proxy's sandbox-proof identity")?;
        Ok(Self {
            socket: run_dir.join(SOCKET_FILE),
            approval_pubkey_hex: hex::encode(approver.verifying_key().to_bytes()),
            identity,
        })
    }

    /// The tool-proxy command both host-tier callers start: the explicit
    /// host-tier opt-in, the spec, the socket and approval key, the
    /// announcement and audit paths, and the identity that proves the launch.
    /// No secret is on it. The caller adds its task token and stdio.
    pub(crate) fn command(
        &self,
        proxy_bin: &Path,
        spec: &Path,
        announce: &Path,
        audit: &Path,
    ) -> tokio::process::Command {
        let mut command = tokio::process::Command::new(proxy_bin);
        command
            .arg(crate::host_tier::TOOL_PROXY_OPT_IN)
            .arg("--spec")
            .arg(spec)
            .args(self.proxy_args())
            .arg("--announce-path")
            .arg(announce)
            .arg("--audit-log")
            .arg(audit)
            .envs(self.identity.env())
            .env("NUCLEUS_TOOL_PROXY_DRAND_ENABLED", "false");
        command
    }

    /// The flags that put the proxy on the socket with no approval secret.
    pub(crate) fn proxy_args(&self) -> [OsString; 4] {
        [
            "--listen-unix".into(),
            self.socket.clone().into_os_string(),
            "--approval-pubkeys".into(),
            self.approval_pubkey_hex.clone().into(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #2446 step 2: the spawned proxy is on the socket, with no approval
    /// secret and no TCP listener. Red before: `--listen 127.0.0.1:0` and
    /// `--approval-secret` were on this command line, and the bridge carried
    /// both secrets.
    #[test]
    fn the_proxy_is_put_on_the_socket_with_no_approval_secret() {
        let dir = tempfile::tempdir().unwrap();
        let args: Vec<String> = LocalProxyTransport::new(dir.path(), &Uuid::new_v4())
            .unwrap()
            .proxy_args()
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args[0], "--listen-unix");
        assert!(args[1].ends_with("/p.sock"), "{args:?}");
        assert_eq!(args[2], "--approval-pubkeys");
        assert_eq!(args[3].len(), 64, "one Ed25519 public key in hex");
        assert!(!args.iter().any(|a| a.contains("secret") || a == "--listen"));
    }

    /// #2446 step 3a: the proxy `run --local` and `shell` start is proven by
    /// the run's own identity, not by a secret. Red before: the command carried
    /// `--auth-secret <hex>` and `NUCLEUS_SANDBOX_TOKEN`, an orchestrator token
    /// HMAC'd with that secret, and no identity.
    #[test]
    fn the_proxy_is_proven_by_the_runs_identity_not_a_secret() {
        let dir = tempfile::tempdir().unwrap();
        let run_id = Uuid::new_v4();
        let transport = LocalProxyTransport::new(dir.path(), &run_id).unwrap();
        let command = transport.command(
            Path::new("nucleus-tool-proxy"),
            &dir.path().join("pod.yaml"),
            &dir.path().join("proxy.addr"),
            &dir.path().join("audit.log"),
        );
        let command = command.as_std();
        let args: Vec<String> = command
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(
            !args.iter().any(|a| a.contains("secret")),
            "no secret on the proxy's argv: {args:?}"
        );
        let env: std::collections::BTreeMap<String, String> = command
            .get_envs()
            .filter_map(|(k, v)| {
                Some((
                    k.to_string_lossy().into_owned(),
                    v?.to_string_lossy().into_owned(),
                ))
            })
            .collect();
        assert!(
            !env.keys()
                .any(|k| k == "NUCLEUS_SANDBOX_TOKEN" || k.contains("SECRET")),
            "no tier-3 token or secret in the proxy's env: {env:?}"
        );
        let cert = std::fs::read_to_string(&env["NUCLEUS_IDENTITY_CERT"]).unwrap();
        let key = std::fs::read_to_string(&env["NUCLEUS_IDENTITY_KEY"]).unwrap();
        let bundle = std::fs::read_to_string(&env["NUCLEUS_IDENTITY_TRUST_BUNDLE"]).unwrap();
        let certificate = nucleus_identity::WorkloadCertificate::from_pem(&cert, &key).unwrap();
        assert_eq!(
            certificate.identity().to_spiffe_uri(),
            format!("spiffe://host-tier.nucleus.local/ns/pods/sa/{run_id}")
        );
        nucleus_identity::verify_svid_chain(
            certificate.leaf(),
            &nucleus_identity::TrustBundle::from_pem(&bundle).unwrap(),
        )
        .unwrap();
    }

    /// The socket path fits macOS's 104-byte limit under a typical temp dir.
    #[test]
    fn the_socket_path_fits_a_macos_temp_dir() {
        let typical = "/var/folders/7k/abcdefghij0123456789klmnop/T/";
        let name = run_dir("nucleus-shell", &Uuid::new_v4());
        let tail = name.file_name().unwrap().to_string_lossy().len() + 1 + SOCKET_FILE.len();
        assert!(typical.len() + tail < 104, "{}", typical.len() + tail);
    }
}
