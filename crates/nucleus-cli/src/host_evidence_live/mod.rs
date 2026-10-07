//! Ordinary live broker transaction; invoked explicitly by the Rust CI gate.
//! Requires Linux, KVM, root, and installed guest artifacts. Never a mock driver.
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{path::Path, time::Duration};
use uuid::Uuid;

pub(crate) mod node;
const CALL_CHARGE: u64 = 1000;

#[derive(Deserialize)]
pub(crate) struct Created {
    pub id: Uuid,
    pub proxy_addr: String,
}

pub(crate) async fn body(response: reqwest::Response) -> Result<Vec<u8>> {
    let status = response.status();
    let bytes = response.bytes().await?;
    ensure!(
        status.is_success(),
        "HTTP {status}: {}",
        String::from_utf8_lossy(&bytes)
    );
    Ok(bytes.to_vec())
}

/// A pod whose only purpose is one credentialed request to the node's fixture
/// upstream, so the host signs an authorization and an outcome for it.
pub(crate) fn effect_pod_spec(upstream: &str) -> serde_json::Value {
    let (issuer, credential) = portcullis::says_admission::mint_credential(&[19; 32], "web_fetch");
    let dlc = nucleus_spec::dlc_admission::DlcProvisioning {
        trusted_keys: hex::encode(issuer),
        issuer: hex::encode(issuer),
        credentials: format!("web_fetch={}", hex::encode(credential.bytes)),
    };
    json!({
        "apiVersion":"nucleus/v1", "kind":"Pod",
        "metadata":{"name":"live-host-evidence", "labels":dlc.labels()},
        "spec":{
            "work_dir":"/work", "timeout_seconds":180,
            "policy":{"type":"inline", "lattice":portcullis::PermissionLattice::permissive()},
            "network":{"allow":[]},
            "credentialed_egress":[{
                "name":"receipt-fixture", "upstream":upstream,
                "credential_env":"NUCLEUS_RECEIPT_FIXTURE_TOKEN",
                "header":"authorization", "value_prefix":"Bearer "
            }],
            "image":{
                "kernel_path":nucleus_spec::microvm_host::guest_kernel_path(),
                "rootfs_path":nucleus_spec::microvm_host::guest_rootfs_path(),
                "read_only":true
            },
            "vsock":{"guest_cid":3,"port":5005}
        }
    })
}

/// The node's host key, exported from its own key file. Pinned before any
/// guest request: a key is never accepted from a log.
pub(crate) async fn host_key(node: &node::Node, bins: &Path) -> Result<String> {
    let key = node::command(
        bins.join("nucleus-hostctl"),
        &[
            "public-key".into(),
            node.state
                .join("cert_root_signing_key.der")
                .into_os_string(),
        ],
    )
    .await?;
    let key = String::from_utf8(key)?.trim().to_owned();
    ensure!(
        key.len() == 64 && key.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid host key export"
    );
    Ok(key)
}

/// Send `nonce` through the guest's credentialed relay to the node's fixture
/// upstream, and require the same bytes back.
pub(crate) async fn relay(proxy_addr: &str, nonce: &str) -> Result<()> {
    let proxy = if proxy_addr.starts_with("http://") {
        proxy_addr.to_owned()
    } else {
        format!("http://{proxy_addr}")
    };
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()?
        .post(format!("{proxy}/v1/egress/receipt-fixture/echo"))
        .header("content-type", "text/plain")
        .header("x-nucleus-approval-wait-seconds", "0")
        .body(nonce.to_owned())
        .send()
        .await?;
    ensure!(
        body(response).await? == nonce.as_bytes(),
        "guest relay changed fixture output"
    );
    Ok(())
}

async fn transaction(node: &node::Node, bins: &Path, nonce: &str) -> Result<()> {
    let spec = effect_pod_spec(&node.upstream);
    let key = host_key(node, bins).await?;
    let created: Created = serde_json::from_slice(
        &body(
            node.client
                .post(format!("{}/v1/pods", node.url))
                .timeout(nucleus_spec::boot_budget::POD_CREATE_CLIENT_TIMEOUT)
                .json(&spec)
                .send()
                .await?,
        )
        .await?,
    )?;
    let result = inspect(node, bins, &created, &key, nonce).await;
    let cleanup = async {
        body(
            node.client
                .post(format!("{}/v1/pods/{}/cancel", node.url, created.id))
                .send()
                .await?,
        )
        .await
    }
    .await;
    match (result, cleanup) {
        (Ok(()), Ok(_)) => Ok(()),
        (Err(e), Ok(_)) => Err(e.context("live evidence pod cancelled")),
        (result, Err(e)) => anyhow::bail!(
            "pod {} cleanup failed: {e}; verification: {result:?}",
            created.id
        ),
    }
}

async fn inspect(
    node: &node::Node,
    bins: &Path,
    pod: &Created,
    key: &str,
    nonce: &str,
) -> Result<()> {
    relay(&pod.proxy_addr, nonce).await?;
    ensure!(
        node.calls.load(std::sync::atomic::Ordering::SeqCst) == 1,
        "expected exactly one authenticated fixture request"
    );
    let dir = node.state.join("pods").join(pod.id.to_string());
    let auth_path = dir.join(nucleus_spec::host_effect::LOG_FILE);
    let outcome_path = dir.join(nucleus_spec::host_effect::outcome::LOG_FILE);
    // The response can reach the guest just before the durable outcome append.
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match std::fs::read_to_string(&outcome_path) {
                Ok(s) if !s.trim().is_empty() => return Ok::<_, anyhow::Error>(()),
                Ok(_) => {}
                Err(e) => return Err(e.into()),
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    // Use the shipped offline verifier, with a key enrolled before admission.
    node::command(
        bins.join("nucleus-audit"),
        &[
            "verify-host-effects".into(),
            "--log".into(),
            auth_path.clone().into_os_string(),
            "--outcomes".into(),
            outcome_path.clone().into_os_string(),
            "--host-pubkey".into(),
            key.into(),
            "--pod".into(),
            pod.id.to_string().into(),
        ],
    )
    .await?;
    let authorization: nucleus_spec::host_effect::SignedAuthorization =
        serde_json::from_str(std::fs::read_to_string(auth_path)?.trim())?;
    ensure!(
        authorization.authorization.operation == "web_fetch",
        "wrong authorized operation"
    );
    let intended = nucleus_spec::host_effect_approval::EffectRequest {
        require_approval: false,
        // The effect binds the proxy's wire spelling; the authorization's
        // operation above is the host's normalized decision label.
        operation: "WebFetch".into(),
        upstream: "receipt-fixture".into(),
        url: format!("{}/echo", node.upstream),
        method: "POST".into(),
        credential_header: "authorization".into(),
        content_type: "text/plain".into(),
        body_sha256: Sha256::digest(nonce.as_bytes()).into(),
        body_bytes: u64::try_from(nonce.len())?,
        call_charge_micro_usd: Some(CALL_CHARGE),
        request_headers: Default::default(),
    };
    ensure!(
        authorization.authorization.effect_sha256 == hex::encode(intended.digest()?)
            && authorization.authorization.subject == intended.url
            && authorization.authorization.call_charge_micro_usd == CALL_CHARGE,
        "host authorized a different effect or charge"
    );
    let outcome: nucleus_spec::host_effect::outcome::SignedOutcome =
        serde_json::from_str(std::fs::read_to_string(outcome_path)?.trim())?;
    ensure!(
        outcome.outcome.termination
            == nucleus_spec::host_effect::outcome::Termination::ResponseRead,
        "host did not observe response completion"
    );
    let response = outcome
        .outcome
        .response
        .context("host outcome has no response")?;
    ensure!(
        response.status == 200
            && response.body_complete
            && response.body_bytes == u64::try_from(nonce.len())?
            && response.body_sha256 == hex::encode(Sha256::digest(nonce.as_bytes())),
        "host outcome does not match the fixture response"
    );
    println!("live host evidence verified for {}", pod.id);
    Ok(())
}

#[tokio::test]
#[ignore = "requires a Linux KVM host; run cargo xtask host-evidence-live"]
async fn real_guest_host_evidence() -> Result<()> {
    ensure!(
        cfg!(target_os = "linux"),
        "live host evidence requires Linux"
    );
    let bins = std::path::PathBuf::from(
        std::env::var_os("NUCLEUS_HOST_EVIDENCE_BIN_DIR").context("missing binary directory")?,
    );
    let witness = std::path::PathBuf::from(
        std::env::var_os("NUCLEUS_HOST_EVIDENCE_WITNESS").context("missing witness path")?,
    );
    let nonce = std::env::var("NUCLEUS_HOST_EVIDENCE_NONCE")?;
    ensure!(!nonce.is_empty(), "missing fixture nonce");
    let mut node = node::Node::start(&bins, &nonce).await?;
    let result = transaction(&node, &bins, &nonce).await;
    node.stop().await?;
    result.with_context(|| node.diagnostics())?;
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(witness)?;
    file.write_all(nonce.as_bytes())?;
    file.sync_all()?;
    Ok(())
}
