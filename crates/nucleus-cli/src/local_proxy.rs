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
//! What stays: `--auth-secret` keys only the tier-3 sandbox token the proxy
//! checks at startup. #2446 step 3 deletes both.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

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

/// The proxy's listener and approval authority for a run in `run_dir`.
pub(crate) struct LocalProxyTransport {
    socket: PathBuf,
    approval_pubkey_hex: String,
}

impl LocalProxyTransport {
    pub(crate) fn new(run_dir: &Path) -> Self {
        // Generated and dropped: only its public half leaves this function.
        let approver = ed25519_dalek::SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        Self {
            socket: run_dir.join(SOCKET_FILE),
            approval_pubkey_hex: hex::encode(approver.verifying_key().to_bytes()),
        }
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
        let dir = run_dir("nucleus-local", &Uuid::new_v4());
        let args: Vec<String> = LocalProxyTransport::new(&dir)
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

    /// The socket path fits macOS's 104-byte limit under a typical temp dir.
    #[test]
    fn the_socket_path_fits_a_macos_temp_dir() {
        let typical = "/var/folders/7k/abcdefghij0123456789klmnop/T/";
        let name = run_dir("nucleus-shell", &Uuid::new_v4());
        let tail = name.file_name().unwrap().to_string_lossy().len() + 1 + SOCKET_FILE.len();
        assert!(typical.len() + tail < 104, "{}", typical.len() + tail);
    }
}
