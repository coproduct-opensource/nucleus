//! Operator host approvals. This surface never uses a guest approval secret.
use anyhow::{Context, Result, bail};
use base64::Engine as _;
use clap::Subcommand;
use nucleus_spec::host_effect::InputLabel;
use nucleus_spec::host_effect_approval::{
    ApprovalCategory, ApprovalDecision, ApprovalReview, ApprovalStatus, ApprovalView,
};
use uuid::Uuid;

use super::{HttpClient, REQUEST_TIMEOUT};

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Print host review metadata as JSON, each with its category: `ordinary`,
    /// or a `declassification` with its input labels (payload contents are not
    /// included)
    List {
        /// Wait for an unexpired pending effect; print only pending entries
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..=86400))]
        wait_secs: Option<u64>,
    },
    /// Inspect and verify the exact host-retained request and payload
    Review { approval_id: Uuid },
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
    if let Command::List {
        wait_secs: Some(seconds),
    } = command
    {
        let approvals = tokio::time::timeout(std::time::Duration::from_secs(*seconds), async {
            loop {
                let mut approvals = list(client, &endpoint).await?;
                let now = unix_now()?;
                approvals.retain(|approval| is_pending(approval, now));
                if !approvals.is_empty() {
                    return Ok::<_, anyhow::Error>(approvals);
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }).await.context("timed out waiting for a pending host approval; no decision was made and pod was not cancelled")??;
        return Ok(serde_json::to_string_pretty(&approvals)?);
    }
    let approvals = list(client, &endpoint).await?;
    let (id, decision) = match command {
        Command::List { wait_secs: _ } => return Ok(serde_json::to_string_pretty(&approvals)?),
        Command::Review { approval_id } => {
            let expected = approvals
                .iter()
                .find(|a| a.id == *approval_id)
                .context("unknown or expired approval")?;
            let (status, body) = client
                .send(
                    reqwest::Method::GET,
                    &format!("{endpoint}/{approval_id}"),
                    &[],
                    &[],
                    REQUEST_TIMEOUT,
                )
                .await?;
            if status != 200 {
                bail!("request review unavailable (HTTP {status})");
            }
            return render_review(
                serde_json::from_slice(&body).context("invalid review response")?,
                expected,
            );
        }
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

async fn list(client: &HttpClient, endpoint: &reqwest::Url) -> Result<Vec<ApprovalView>> {
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
    serde_json::from_slice(&body).context("invalid host approval response")
}

fn unix_now() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs())
}

fn is_pending(approval: &ApprovalView, now: u64) -> bool {
    approval.status == ApprovalStatus::Pending && now < approval.expires_unix
}

fn pending(approvals: &[ApprovalView], id: Uuid) -> Result<&ApprovalView> {
    let mut matches = approvals.iter().filter(|a| a.id == id);
    let approval = matches
        .next()
        .context("approval is unknown or expired; refresh the list")?;
    if matches.next().is_some() {
        bail!("ambiguous host approval response");
    }
    if !is_pending(approval, unix_now()?) {
        bail!("approval is no longer pending or has expired; refresh the list");
    }
    Ok(approval)
}

fn render_review(review: ApprovalReview, expected: &ApprovalView) -> Result<String> {
    let body = base64::engine::general_purpose::STANDARD
        .decode(&review.body_base64)
        .context("invalid review payload encoding")?;
    let digest = hex::encode(review.request.digest()?);
    if review.approval.id != expected.id
        || digest != parse_hash(&expected.effect_sha256).map_err(anyhow::Error::msg)?
        || digest != parse_hash(&review.approval.effect_sha256).map_err(anyhow::Error::msg)?
        || !review.request.matches_body(&body)
        || review.request.url != expected.subject
        || review.approval.operation != expected.operation
        || review.request.call_charge_micro_usd != Some(expected.call_charge_micro_usd)
        || review.approval.category != expected.category
    {
        bail!("request review does not match the host approval; do not grant it");
    }
    let mut rendered = serde_json::json!({
        "approval": review.approval, "request": review.request,
        "body_base64": review.body_base64, "body_utf8": String::from_utf8(body).ok(),
    });
    match review.approval.category {
        ApprovalCategory::Ordinary => {}
        ApprovalCategory::Declassification { input } => {
            rendered["declassification"] = declassification(&review, input)?;
        }
    }
    Ok(serde_json::to_string_pretty(&rendered)?)
}

/// What granting a held request does, said before the operator decides
/// (#3258). The labels are the host's, carried on the approval it listed;
/// this only words them and names the verified request they would reach.
fn declassification(review: &ApprovalReview, input: InputLabel) -> Result<serde_json::Value> {
    let url = reqwest::Url::parse(&review.request.url).context("invalid reviewed URL")?;
    let mut query_parameter_names: Vec<String> = Vec::new();
    for (name, _) in url.query_pairs() {
        if !query_parameter_names.iter().any(|seen| *seen == name) {
            query_parameter_names.push(name.into_owned());
        }
    }
    Ok(serde_json::json!({
        "notice": "GRANTING THIS APPROVAL DECLASSIFIES TAINTED DATA: the session holds data labelled below, and this one request would carry it to the sink",
        "input": input,
        "input_described": input.describe(),
        "sink": {
            "operation": review.approval.operation,
            "subject": review.approval.subject,
        },
        "bound_request": {
            "method": review.request.method,
            "url": review.request.url,
            "query_parameter_names": query_parameter_names,
            "forwarded_header_names": review.request.request_headers.keys().collect::<Vec<_>>(),
            "body_sha256": hex::encode(review.request.body_sha256),
            "body_bytes": review.request.body_bytes,
        },
    }))
}

#[cfg(test)]
mod tests;
