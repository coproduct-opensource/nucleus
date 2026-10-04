//! Operator host approvals. This surface never uses a guest approval secret.
use anyhow::{Context, Result, bail};
use clap::Subcommand;
use nucleus_spec::host_effect_approval::{ApprovalDecision, ApprovalStatus, ApprovalView};
use uuid::Uuid;

use super::{HttpClient, REQUEST_TIMEOUT};

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Print host review metadata as JSON (payload contents are not included)
    List,
    /// Grant one pending effect matching the reviewed SHA-256 digest
    Grant {
        approval_id: Uuid,
        #[arg(long, value_parser = parse_hash)]
        effect_sha256: String,
    },
    /// Refuse one pending effect
    Refuse { approval_id: Uuid },
}

fn parse_hash(value: &str) -> Result<String, String> {
    let bytes =
        hex::decode(value).map_err(|_| "effect SHA-256 must be 64 hexadecimal characters")?;
    if bytes.len() != 32 {
        return Err("effect SHA-256 must be 64 hexadecimal characters".into());
    }
    Ok(hex::encode(bytes))
}

pub(super) async fn run(
    client: &HttpClient,
    url: &str,
    pod: Uuid,
    command: &Command,
) -> Result<String> {
    if !matches!(client, HttpClient::Mtls(_)) {
        bail!(
            "host approvals require the operator's mTLS identity; run nucleus setup or supply --tls-cert, --tls-key and --trust-bundle"
        );
    }
    let base = reqwest::Url::parse(url).context("invalid node URL")?;
    if base.scheme() != "https"
        || !base.username().is_empty()
        || base.password().is_some()
        || base.query().is_some()
        || base.fragment().is_some()
        || base.path() != "/"
    {
        bail!(
            "host approvals require an HTTPS node origin without a path, credentials, query or fragment"
        );
    }
    let endpoint = base.join(&format!("/v1/pods/{pod}/effect-approvals"))?;
    let (status, body) = client
        .send(
            reqwest::Method::GET,
            endpoint.as_str(),
            &[],
            &[],
            REQUEST_TIMEOUT,
        )
        .await?;
    if status != 200 {
        bail!(
            "listing host approvals failed (HTTP {status}); the configured node operator identity is required"
        );
    }
    let approvals: Vec<ApprovalView> =
        serde_json::from_slice(&body).context("invalid host approval response")?;
    let (id, decision) = match command {
        Command::List => return Ok(serde_json::to_string_pretty(&approvals)?),
        Command::Grant {
            approval_id,
            effect_sha256,
        } => {
            let approval = pending(&approvals, *approval_id)?;
            if parse_hash(&approval.effect_sha256).map_err(anyhow::Error::msg)?
                != parse_hash(effect_sha256).map_err(anyhow::Error::msg)?
            {
                bail!("effect hash differs from the reviewed effect; no approval was granted");
            }
            (*approval_id, ApprovalDecision::Grant)
        }
        Command::Refuse { approval_id } => {
            pending(&approvals, *approval_id)?;
            (*approval_id, ApprovalDecision::Refuse)
        }
    };
    let body = serde_json::to_vec(&decision)?;
    let headers = vec![("content-type".into(), "application/json".into())];
    let (status, _) = client
        .send(
            reqwest::Method::POST,
            &format!("{endpoint}/{id}"),
            &headers,
            &body,
            REQUEST_TIMEOUT,
        )
        .await?;
    if status != 204 {
        bail!("settling host approval failed (HTTP {status}); refresh the list before retrying");
    }
    Ok(format!(
        "{} approval {id} for pod {pod}",
        match decision {
            ApprovalDecision::Grant => "Granted",
            ApprovalDecision::Refuse => "Refused",
        }
    ))
}

fn pending(approvals: &[ApprovalView], id: Uuid) -> Result<&ApprovalView> {
    let mut matches = approvals.iter().filter(|a| a.id == id);
    let approval = matches
        .next()
        .context("approval is unknown or expired; refresh the list")?;
    if matches.next().is_some() {
        bail!("ambiguous host approval response");
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    if approval.status != ApprovalStatus::Pending || now >= approval.expires_unix {
        bail!("approval is no longer pending or has expired; refresh the list");
    }
    Ok(approval)
}

#[cfg(test)]
mod tests;
