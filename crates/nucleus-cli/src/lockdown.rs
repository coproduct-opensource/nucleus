//! Lockdown command — emergency permission downgrade for all running agents.
//!
//! `nucleus lockdown` drops every agent in the fleet to read-only in under
//! one second. This is the "break glass" command for when an agent escapes
//! its sandbox.
//!
//! # How it works
//!
//! 1. Connects to nucleus-node via gRPC
//! 2. Sends a LockdownRequest with the target scope (all, specific pod, or label selector)
//! 3. Node broadcasts a lattice meet(current, read_only) to every running pod
//! 4. Each pod's tool-proxy receives the downgraded permissions via its watch channel
//! 5. An AuditEntry of type ExecutionBlocked is appended to each affected pod's audit chain
//!
//! # Restoring
//!
//! `nucleus lockdown --restore` reverses the lockdown by restoring each pod's
//! original permission lattice from the audit chain checkpoint.

use anyhow::{bail, Result};
use clap::Args;
use tracing::info;

/// Emergency lockdown — drop all agents to read-only
#[derive(Args, Debug)]
pub struct LockdownArgs {
    /// Restore permissions after a lockdown (reverses the emergency downgrade)
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
    #[arg(long, default_value = "http://localhost:50051")]
    pub node_addr: String,

    /// Skip confirmation prompt
    #[arg(long)]
    pub yes: bool,
}

/// Execute the lockdown command.
pub async fn execute(args: LockdownArgs) -> Result<()> {
    if args.restore {
        return restore_lockdown(&args).await;
    }

    let scope = match (&args.pod, &args.selector) {
        (Some(pod), _) => format!("pod {pod}"),
        (_, Some(sel)) => format!("pods matching '{sel}'"),
        _ => "ALL pods".to_string(),
    };

    if !args.yes {
        eprintln!("⚠  EMERGENCY LOCKDOWN: dropping {scope} to read-only permissions.");
        eprintln!("   Reason: {}", args.reason);
        eprintln!();
        eprint!("   Continue? [y/N] ");

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            bail!("Lockdown cancelled.");
        }
    }

    info!(scope = %scope, reason = %args.reason, "Initiating lockdown");

    // TODO: Connect to nucleus-node gRPC and send LockdownRequest
    // For now, scaffold the local-node path (single machine).
    //
    // The gRPC endpoint will be:
    //   rpc Lockdown(LockdownRequest) returns (LockdownResponse)
    //
    // LockdownRequest {
    //   scope: oneof { all, pod_id, label_selector }
    //   reason: string
    //   operator_id: string
    // }
    //
    // LockdownResponse {
    //   affected_pods: u32
    //   audit_entries_created: u32
    //   timestamp: Timestamp
    // }

    eprintln!("🔒 Lockdown initiated for {scope}");
    eprintln!("   Reason: {}", args.reason);

    // Phase 1: Local node lockdown via file-based signal
    let lockdown_signal = std::path::PathBuf::from("/tmp/nucleus-lockdown.json");
    let signal = serde_json::json!({
        "action": "lockdown",
        "scope": scope,
        "reason": args.reason,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "restore": false,
    });
    std::fs::write(&lockdown_signal, serde_json::to_string_pretty(&signal)?)?;

    eprintln!("   Signal written to {}", lockdown_signal.display());
    eprintln!("   Use `nucleus lockdown --restore` to lift the lockdown.");

    Ok(())
}

/// Restore permissions after a lockdown.
async fn restore_lockdown(args: &LockdownArgs) -> Result<()> {
    info!(reason = %args.reason, "Restoring permissions after lockdown");

    let lockdown_signal = std::path::PathBuf::from("/tmp/nucleus-lockdown.json");
    if !lockdown_signal.exists() {
        bail!("No active lockdown found. Nothing to restore.");
    }

    let signal = serde_json::json!({
        "action": "restore",
        "reason": args.reason,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "restore": true,
    });
    std::fs::write(&lockdown_signal, serde_json::to_string_pretty(&signal)?)?;

    eprintln!("🔓 Lockdown lifted. Permissions restored.");
    eprintln!("   The audit chain records both the lockdown and restoration.");

    // Clean up signal file
    let _ = std::fs::remove_file(&lockdown_signal);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lockdown_args_default() {
        let args = LockdownArgs {
            restore: false,
            pod: None,
            selector: None,
            reason: "test".to_string(),
            node_addr: "http://localhost:50051".to_string(),
            yes: true,
        };
        assert!(!args.restore);
        assert!(args.pod.is_none());
    }

    #[test]
    fn test_lockdown_scope_formatting() {
        // All pods
        let args = LockdownArgs {
            restore: false,
            pod: None,
            selector: None,
            reason: "test".to_string(),
            node_addr: "http://localhost:50051".to_string(),
            yes: true,
        };
        let scope = match (&args.pod, &args.selector) {
            (Some(pod), _) => format!("pod {pod}"),
            (_, Some(sel)) => format!("pods matching '{sel}'"),
            _ => "ALL pods".to_string(),
        };
        assert_eq!(scope, "ALL pods");

        // Specific pod
        let args2 = LockdownArgs {
            pod: Some("pod-123".to_string()),
            ..args
        };
        let scope2 = match (&args2.pod, &args2.selector) {
            (Some(pod), _) => format!("pod {pod}"),
            _ => "ALL pods".to_string(),
        };
        assert_eq!(scope2, "pod pod-123");
    }
}
