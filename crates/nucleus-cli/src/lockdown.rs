//! Lockdown command — emergency permission downgrade for all running agents.
//!
//! `nucleus lockdown` drops every agent in the fleet to read-only in under
//! one second. This is the "break glass" command for when an agent escapes
//! its sandbox.
//!
//! # How it works
//!
//! Uses the operator-authenticated mTLS `NodeService::Lockdown` RPC.
//! An unavailable node is an error, never a downgrade to a local signal file.

use anyhow::{Result, bail};
use clap::Args;
use tracing::info;

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
    #[arg(long, default_value = "https://127.0.0.1:9180")]
    pub node_addr: String,

    /// Skip confirmation prompt
    #[arg(long)]
    pub yes: bool,
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

    let response = try_grpc_lockdown(&args, &scope).await?;
    eprintln!(
        "Lockdown {action} accepted by node: {} pods affected, {} audit entries.",
        response.affected_pods, response.audit_entries_created
    );

    Ok(())
}

/// Try to execute lockdown via gRPC to nucleus-node.
async fn try_grpc_lockdown(
    args: &LockdownArgs,
    _scope: &str,
) -> Result<nucleus_proto::nucleus_node::LockdownResponse> {
    use nucleus_proto::nucleus_node::node_service_client::NodeServiceClient;

    let mut client = NodeServiceClient::new(operator_channel(&args.node_addr).await?);

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

/// Present the provisioned operator SVID and accept only the node's SVID.
async fn operator_channel(url: &str) -> Result<tonic::transport::Channel> {
    use nucleus_identity::node_tls::NodeServerVerifier;
    use nucleus_identity::tls::root_store_from_trust_bundle;
    use nucleus_identity::{TrustBundle, WorkloadCertificate};
    use std::sync::Arc;
    use tonic::transport::{Channel, ClientTlsConfig, Identity};
    if reqwest::Url::parse(url)?.scheme() != "https" {
        bail!("lockdown requires an https:// node endpoint and an operator mTLS identity");
    }
    let dir = crate::config::Config::identity_dir()?;
    let cert = std::fs::read_to_string(dir.join("cli-cert.pem"))?;
    let key = std::fs::read_to_string(dir.join("cli-key.pem"))?;
    let bundle = TrustBundle::from_pem(&std::fs::read_to_string(dir.join("trust-bundle.pem"))?)?;
    let own = WorkloadCertificate::from_pem(&cert, &key)?;
    let node = nucleus_identity::Identity::node(own.identity().trust_domain())?;
    let verifier =
        NodeServerVerifier::new(Arc::new(root_store_from_trust_bundle(&bundle)?), &node)?;
    Ok(Channel::from_shared(url.to_string())?
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(30))
        .tls_config_with_verifier(
            ClientTlsConfig::new().identity(Identity::from_pem(cert, key)),
            Arc::new(verifier),
        )?
        .connect()
        .await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn plaintext_lockdown_cannot_fall_back_to_a_file() {
        let error = operator_channel("http://127.0.0.1:9180").await.unwrap_err();
        assert!(error.to_string().contains("https://"));
    }

    #[test]
    fn test_scope_formatting() {
        let args = LockdownArgs {
            restore: false,
            pod: None,
            selector: None,
            reason: "test".to_string(),
            node_addr: "https://127.0.0.1:9180".to_string(),
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
