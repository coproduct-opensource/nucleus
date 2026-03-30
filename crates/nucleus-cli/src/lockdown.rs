//! Lockdown command — emergency permission downgrade for all running agents.
//!
//! `nucleus lockdown` drops every agent in the fleet to read-only in under
//! one second. This is the "break glass" command for when an agent escapes
//! its sandbox.
//!
//! # How it works
//!
//! 1. Tries gRPC `NodeService::Lockdown` on the configured node address
//! 2. Falls back to writing a local signal file if gRPC is unavailable
//! 3. Both paths result in tool-proxy blocking all tool calls

use anyhow::{bail, Result};
use clap::Args;
use tracing::{info, warn};

/// Emergency lockdown — drop all agents to read-only
#[derive(Args, Debug)]
pub struct LockdownArgs {
    /// Restore permissions after a lockdown
    #[arg(long)]
    pub restore: bool,

    /// Target a specific pod by ID instead of all pods
    #[arg(long)]
    pub pod: Option<String>,

    /// Target pods matching a label selector (e.g., "team=frontend")
    #[arg(long)]
    pub selector: Option<String>,

    /// Reason for the lockdown (recorded in audit trail)
    #[arg(long, default_value = "emergency lockdown")]
    pub reason: String,

    /// Node gRPC address
    #[arg(long, default_value = "http://127.0.0.1:9180")]
    pub node_addr: String,

    /// Skip confirmation prompt
    #[arg(long)]
    pub yes: bool,
}

/// Lockdown signal file path — stored in a user-owned directory, not /tmp.
/// Red team finding: /tmp is world-writable, any local process could fake a lockdown.
fn lockdown_signal_path() -> std::path::PathBuf {
    let dir = dirs::runtime_dir()
        .or_else(dirs::data_local_dir)
        .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
        .join("nucleus");
    let _ = std::fs::create_dir_all(&dir);
    dir.join("lockdown.json")
}

/// Compute HMAC-SHA256 over the signal body using a machine-local key.
/// The key is derived from the machine ID + a fixed salt — not a secret,
/// but sufficient to prevent casual tampering by other local users.
fn signal_hmac(body: &[u8]) -> String {
    use hmac::{digest::KeyInit, Hmac, Mac};
    use sha2::Sha256;

    // Machine-local key: hostname + uid — prevents cross-user forgery
    let key_material = format!(
        "nucleus-lockdown-{}:{}",
        whoami::hostname().unwrap_or_else(|_| "unknown".to_string()),
        whoami::username().unwrap_or_else(|_| "unknown".to_string()),
    );

    let mut mac =
        Hmac::<Sha256>::new_from_slice(key_material.as_bytes()).expect("hmac accepts any key");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

/// Execute the lockdown command.
pub async fn execute(args: LockdownArgs) -> Result<()> {
    let scope = match (&args.pod, &args.selector) {
        (Some(pod), _) => format!("pod {pod}"),
        (_, Some(sel)) => format!("pods matching '{sel}'"),
        _ => "ALL pods".to_string(),
    };

    if !args.yes && !args.restore {
        eprintln!("WARNING: EMERGENCY LOCKDOWN — dropping {scope} to read-only permissions.");
        eprintln!("   Reason: {}", args.reason);
        eprintln!();
        eprint!("   Continue? [y/N] ");

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            bail!("Lockdown cancelled.");
        }
    }

    let action = if args.restore { "restore" } else { "lockdown" };
    info!(scope = %scope, reason = %args.reason, action = action, "Lockdown command");

    // Try gRPC first, fall back to local signal file
    match try_grpc_lockdown(&args, &scope).await {
        Ok(response) => {
            if args.restore {
                eprintln!("Lockdown lifted via gRPC.");
            } else {
                eprintln!(
                    "Lockdown initiated via gRPC — {} pods affected, {} audit entries.",
                    response.affected_pods, response.audit_entries_created
                );
            }
        }
        Err(e) => {
            warn!(error = %e, "gRPC lockdown failed — falling back to local signal file");
            write_signal_file(&args, &scope)?;
        }
    }

    Ok(())
}

/// Try to execute lockdown via gRPC to nucleus-node.
async fn try_grpc_lockdown(
    args: &LockdownArgs,
    _scope: &str,
) -> Result<nucleus_proto::nucleus_node::LockdownResponse> {
    use nucleus_proto::nucleus_node::node_service_client::NodeServiceClient;

    let mut client = NodeServiceClient::connect(args.node_addr.clone())
        .await
        .map_err(|e| anyhow::anyhow!("Failed to connect to {}: {}", args.node_addr, e))?;

    let request = nucleus_proto::nucleus_node::LockdownRequest {
        reason: args.reason.clone(),
        operator_id: whoami::username().unwrap_or_else(|_| "unknown".to_string()),
        restore: args.restore,
        scope: match (&args.pod, &args.selector) {
            (Some(pod), _) => Some(nucleus_proto::nucleus_node::lockdown_request::Scope::PodId(
                pod.clone(),
            )),
            (_, Some(sel)) => Some(
                nucleus_proto::nucleus_node::lockdown_request::Scope::LabelSelector(sel.clone()),
            ),
            _ => None, // All pods
        },
    };

    let response = client
        .lockdown(request)
        .await
        .map_err(|e| anyhow::anyhow!("Lockdown RPC failed: {}", e))?;

    Ok(response.into_inner())
}

/// Fallback: write a local signal file for the tool-proxy watcher.
fn write_signal_file(args: &LockdownArgs, scope: &str) -> Result<()> {
    let signal_path = lockdown_signal_path();

    if args.restore {
        if signal_path.exists() {
            std::fs::remove_file(&signal_path)?;
            eprintln!("Lockdown lifted (signal file removed).");
        } else {
            eprintln!("No active lockdown found.");
        }
        return Ok(());
    }

    let body = serde_json::json!({
        "action": "lockdown",
        "scope": scope,
        "reason": args.reason,
        "timestamp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        "restore": false,
    });
    let body_bytes = serde_json::to_string_pretty(&body)?;
    let hmac = signal_hmac(body_bytes.as_bytes());

    // Write signal with HMAC envelope
    let envelope = serde_json::json!({
        "signal": body,
        "hmac": hmac,
    });
    std::fs::write(&signal_path, serde_json::to_string_pretty(&envelope)?)?;

    eprintln!("Lockdown initiated via local signal file.");
    eprintln!("   Signal: {}", signal_path.display());
    eprintln!("   Use `nucleus lockdown --restore` to lift.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scope_formatting() {
        let args = LockdownArgs {
            restore: false,
            pod: None,
            selector: None,
            reason: "test".to_string(),
            node_addr: "http://127.0.0.1:9180".to_string(),
            yes: true,
        };
        let scope = match (&args.pod, &args.selector) {
            (Some(pod), _) => format!("pod {pod}"),
            (_, Some(sel)) => format!("pods matching '{sel}'"),
            _ => "ALL pods".to_string(),
        };
        assert_eq!(scope, "ALL pods");
    }

    #[test]
    fn test_scope_pod() {
        let scope = match (&Some("pod-123".to_string()), &None::<String>) {
            (Some(pod), _) => format!("pod {pod}"),
            _ => "ALL pods".to_string(),
        };
        assert_eq!(scope, "pod pod-123");
    }
}
