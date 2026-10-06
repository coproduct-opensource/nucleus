//! This node's platform evidence: a TPM quote over its boot, bound to its
//! executor key (#2706, ADR 0011). The Attester role of RFC 9334.
//!
//! Two states, chosen once at startup and never downgraded:
//!
//! * [`NodePlatformSource::Unattested`] — no TPM was configured. Every
//!   execution receipt records `Unattested` with the reason. That is an honest
//!   tier, and the node never claims more.
//! * [`NodePlatformSource::Tpm`] — `--node-evidence-tpm` names a device. A
//!   device that cannot be opened, or a first quote that fails, stops startup:
//!   an operator who asked for attestation does not get a node that silently
//!   runs without it. The node re-quotes every epoch (freshness = counter +
//!   time) and stores each evidence document by its SHA-256; a receipt records
//!   the digest and epoch in force when it was signed, so a stranger can fetch
//!   that document and appraise it offline. A verifier may also send a nonce
//!   for a fresh challenge-response quote.
//!
//! Every quote's qualifying data binds the executor key that signs receipts
//! and, when the node is a federation issuer, the digest of its JWKS.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use axum::Json;
use axum::extract::{Path as UrlPath, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use nucleus_ci_verdict::execution::NodePlatform;
use nucleus_node_evidence::attester::{
    AkTemplate, Attester, DeviceTransport, LogSources, Tpm, default_pcrs,
};
use nucleus_node_evidence::{
    AkAnchorClaim, ExecutorKey, Federation, Freshness, KeyBinding, Nonce, evidence_digest,
};
use tracing::{info, warn};

use crate::NodeState;

/// Operator flags for node platform evidence.
#[derive(clap::Args, Debug, Clone)]
pub(crate) struct NodeEvidenceArgs {
    /// The TPM device to attest this node's boot with (e.g. `/dev/tpmrm0`).
    /// Unset: receipts record `Unattested`. Set: a TPM that cannot be used is
    /// a startup error, never a silent downgrade.
    #[arg(long, env = "NUCLEUS_NODE_EVIDENCE_TPM")]
    node_evidence_tpm: Option<PathBuf>,
    /// Where the attestation key's template comes from: `default-ecc`, or
    /// `nv:<index>` for a template a cloud provider publishes in NV (e.g.
    /// `nv:0x01c10003`), whose key the provider's API then vouches for.
    #[arg(
        long,
        env = "NUCLEUS_NODE_EVIDENCE_AK_TEMPLATE",
        default_value = "default-ecc"
    )]
    node_evidence_ak_template: String,
    /// The anchor this node claims for its AK: `none`, or `operator:<source>`
    /// naming where the operator fetched the AK from. A claim only; the
    /// relying party's own pin decides whether it anchors anything.
    #[arg(long, env = "NUCLEUS_NODE_EVIDENCE_ANCHOR", default_value = "none")]
    node_evidence_anchor: String,
    /// Seconds between epoch re-quotes.
    #[arg(long, env = "NUCLEUS_NODE_EVIDENCE_EPOCH_SECS", default_value_t = 300)]
    node_evidence_epoch_secs: u64,
}

fn parse_template(s: &str) -> Result<AkTemplate, String> {
    match s.strip_prefix("nv:") {
        None if s == "default-ecc" => Ok(AkTemplate::DefaultEccP256),
        None => Err(format!(
            "--node-evidence-ak-template {s:?}: expected `default-ecc` or `nv:<index>`"
        )),
        Some(index) => {
            let digits = index.trim_start_matches("0x");
            u32::from_str_radix(digits, 16)
                .map(AkTemplate::NvIndex)
                .map_err(|e| format!("--node-evidence-ak-template {s:?}: {e}"))
        }
    }
}

fn parse_anchor(s: &str) -> Result<AkAnchorClaim, String> {
    match s.strip_prefix("operator:") {
        Some(source) if !source.is_empty() => Ok(AkAnchorClaim::OperatorFetched {
            source: source.to_string(),
        }),
        Some(_) => Err("--node-evidence-anchor operator: needs a source".into()),
        None if s == "none" => Ok(AkAnchorClaim::None),
        None => Err(format!(
            "--node-evidence-anchor {s:?}: expected `none` or `operator:<source>`"
        )),
    }
}

/// The epoch in force: the counter and the stored document's digest.
#[derive(Clone, Debug)]
struct Epoch {
    counter: u64,
    digest: String,
}

/// A node with a TPM.
pub(crate) struct TpmNode {
    attester: Mutex<Attester<DeviceTransport>>,
    executor_key: [u8; 32],
    /// The state dir holding the federation keyring, when federation is on.
    federation_dir: Option<PathBuf>,
    store: PathBuf,
    latest: RwLock<Epoch>,
    epoch_secs: u64,
    /// One challenge quote at a time; a second concurrent one is refused.
    challenge: tokio::sync::Semaphore,
}

/// This node's platform evidence source.
pub(crate) enum NodePlatformSource {
    /// No TPM configured; the reason is recorded on every receipt.
    Unattested(String),
    /// A TPM attests this node.
    Tpm(Arc<TpmNode>),
}

fn unix_now() -> Result<i64, String> {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("clock: {e}"))?;
    i64::try_from(d.as_secs()).map_err(|e| format!("clock: {e}"))
}

fn is_digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Write `bytes` to `path` atomically (temp file + rename).
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes).map_err(|e| format!("writing {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("renaming {}: {e}", path.display()))
}

impl TpmNode {
    fn binding(&self) -> Result<KeyBinding, String> {
        let federation = match &self.federation_dir {
            None => Federation::NotFederated,
            Some(dir) => {
                let now = u64::try_from(unix_now()?).map_err(|e| e.to_string())?;
                let state = nucleus_federation::keyring::KeyDir::new(dir)
                    .state(now)
                    .map_err(|e| format!("federation keyring: {e}"))?;
                let jwks = serde_json::to_vec(&state.jwks()).map_err(|e| e.to_string())?;
                Federation::JwksSha256(evidence_digest(&jwks))
            }
        };
        Ok(KeyBinding {
            executor_key: ExecutorKey::Ed25519(self.executor_key),
            federation,
        })
    }

    fn quote(&self, freshness: Freshness) -> Result<Vec<u8>, String> {
        let binding = self.binding()?;
        let mut attester = self
            .attester
            .lock()
            .map_err(|_| "TPM attester lock poisoned".to_string())?;
        let evidence = attester
            .attest(&binding, freshness)
            .map_err(|e| format!("TPM quote: {e}"))?;
        serde_json::to_vec_pretty(&evidence).map_err(|e| e.to_string())
    }

    /// Take the next epoch quote, store it, and make it the one in force.
    fn advance_epoch(&self) -> Result<Epoch, String> {
        let counter = self
            .latest
            .read()
            .map_err(|_| "epoch lock poisoned".to_string())?
            .counter
            .saturating_add(1);
        let bytes = self.quote(Freshness::Epoch {
            counter,
            iat: unix_now()?,
        })?;
        let digest = hex::encode(evidence_digest(&bytes));
        write_atomic(&self.store.join(format!("{digest}.json")), &bytes)?;
        write_atomic(&self.store.join("epoch"), counter.to_string().as_bytes())?;
        let epoch = Epoch { counter, digest };
        *self
            .latest
            .write()
            .map_err(|_| "epoch lock poisoned".to_string())? = epoch.clone();
        Ok(epoch)
    }

    fn stored(&self, digest: &str) -> Option<Vec<u8>> {
        if !is_digest(digest) {
            return None;
        }
        std::fs::read(self.store.join(format!("{digest}.json"))).ok()
    }
}

impl NodePlatformSource {
    /// Decide the source at startup. With a TPM configured, the first epoch
    /// quote is taken here, so a node that serves has evidence in force.
    pub(crate) fn start(
        args: &NodeEvidenceArgs,
        state_dir: &Path,
        executor_key: [u8; 32],
        federated: bool,
    ) -> Result<Self, String> {
        let Some(device) = &args.node_evidence_tpm else {
            return Ok(Self::Unattested(
                "no TPM attester configured (--node-evidence-tpm is unset)".into(),
            ));
        };
        let template = parse_template(&args.node_evidence_ak_template)?;
        let anchor = parse_anchor(&args.node_evidence_anchor)?;
        if args.node_evidence_epoch_secs == 0 {
            return Err("--node-evidence-epoch-secs must be positive".into());
        }
        let transport = DeviceTransport::open(device)
            .map_err(|e| format!("--node-evidence-tpm {}: {e}", device.display()))?;
        let store = state_dir.join("node-evidence");
        std::fs::create_dir_all(&store)
            .map_err(|e| format!("creating {}: {e}", store.display()))?;
        // The counter survives restarts so an epoch number is never reused.
        let previous = std::fs::read_to_string(store.join("epoch"))
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0);
        let node = Arc::new(TpmNode {
            attester: Mutex::new(Attester::new(
                Tpm::new(transport),
                template,
                default_pcrs(),
                LogSources::linux(),
                anchor,
            )),
            executor_key,
            federation_dir: federated.then(|| state_dir.to_path_buf()),
            store,
            latest: RwLock::new(Epoch {
                counter: previous,
                digest: String::new(),
            }),
            epoch_secs: args.node_evidence_epoch_secs,
            challenge: tokio::sync::Semaphore::new(1),
        });
        let first = node.advance_epoch()?;
        info!(
            epoch = first.counter,
            evidence_sha256 = %first.digest,
            "node platform evidence: TPM attester ready"
        );
        Ok(Self::Tpm(node))
    }

    /// Re-quote every epoch. A failed quote keeps the previous epoch in
    /// force; receipts signed meanwhile name it, and a verifier's maximum age
    /// turns them `Expired` rather than anything stronger.
    pub(crate) fn spawn_epochs(&self) {
        let Self::Tpm(node) = self else { return };
        let node = Arc::clone(node);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(node.epoch_secs));
            tick.tick().await;
            loop {
                tick.tick().await;
                let n = Arc::clone(&node);
                match tokio::task::spawn_blocking(move || n.advance_epoch()).await {
                    Ok(Ok(e)) => {
                        info!(epoch = e.counter, evidence_sha256 = %e.digest, "node evidence epoch")
                    }
                    Ok(Err(e)) => {
                        warn!(error = %e, "node evidence epoch failed; previous epoch stays in force")
                    }
                    Err(e) => warn!(error = %e, "node evidence epoch task failed"),
                }
            }
        });
    }

    /// What a receipt signed now records.
    pub(crate) fn platform(&self) -> NodePlatform {
        match self {
            Self::Unattested(reason) => NodePlatform::Unattested {
                reason: reason.clone(),
            },
            Self::Tpm(node) => match node.latest.read() {
                Ok(e) => NodePlatform::Evidence {
                    evidence_sha256: e.digest.clone(),
                    epoch: e.counter,
                },
                Err(_) => NodePlatform::Unattested {
                    reason: "epoch state unavailable (lock poisoned)".into(),
                },
            },
        }
    }
}

fn evidence_response(bytes: Vec<u8>) -> Response {
    ([(header::CONTENT_TYPE, "application/json")], bytes).into_response()
}

fn unattested(reason: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({ "unattested": reason })),
    )
        .into_response()
}

/// `GET /v1/node/evidence` — the epoch evidence in force.
async fn latest(State(state): State<NodeState>) -> Response {
    match state.node_platform.as_ref() {
        NodePlatformSource::Unattested(reason) => unattested(reason),
        NodePlatformSource::Tpm(node) => {
            let digest = node.latest.read().map(|e| e.digest.clone());
            match digest.ok().and_then(|d| node.stored(&d)) {
                Some(bytes) => evidence_response(bytes),
                None => StatusCode::SERVICE_UNAVAILABLE.into_response(),
            }
        }
    }
}

/// `GET /v1/node/evidence/{sha256}` — a stored epoch document, by the digest
/// a receipt names. Immutable: the bytes hash to the name.
async fn by_digest(State(state): State<NodeState>, UrlPath(digest): UrlPath<String>) -> Response {
    match state.node_platform.as_ref() {
        NodePlatformSource::Unattested(reason) => unattested(reason),
        NodePlatformSource::Tpm(node) => match node.stored(&digest) {
            Some(bytes) => evidence_response(bytes),
            None => StatusCode::NOT_FOUND.into_response(),
        },
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ChallengeRequest {
    /// The verifier's nonce, hex, 16 to 64 bytes.
    nonce: Nonce,
}

/// `POST /v1/node/evidence/challenge` — a fresh quote over the caller's nonce.
async fn challenge(State(state): State<NodeState>, Json(req): Json<ChallengeRequest>) -> Response {
    let node = match state.node_platform.as_ref() {
        NodePlatformSource::Unattested(reason) => return unattested(reason),
        NodePlatformSource::Tpm(node) => Arc::clone(node),
    };
    let Ok(_permit) = node.challenge.try_acquire() else {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            "a challenge quote is in progress",
        )
            .into_response();
    };
    let n = Arc::clone(&node);
    let freshness = Freshness::Challenge {
        eat_nonce: req.nonce,
    };
    match tokio::task::spawn_blocking(move || n.quote(freshness)).await {
        Ok(Ok(bytes)) => evidence_response(bytes),
        Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// The evidence routes. Public: evidence is not secret, and a relying party
/// that checks a receipt need hold no node credential to fetch it.
pub(crate) fn routes() -> axum::Router<NodeState> {
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/v1/node/evidence", get(latest))
        .route("/v1/node/evidence/challenge", post(challenge))
        .route("/v1/node/evidence/{digest}", get(by_digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_parse_strictly() {
        assert_eq!(
            parse_template("nv:0x01c10003"),
            Ok(AkTemplate::NvIndex(0x01c1_0003))
        );
        assert_eq!(
            parse_template("default-ecc"),
            Ok(AkTemplate::DefaultEccP256)
        );
        assert!(parse_template("rsa").is_err());
        assert_eq!(parse_anchor("none"), Ok(AkAnchorClaim::None));
        assert_eq!(
            parse_anchor("operator:cloud-api"),
            Ok(AkAnchorClaim::OperatorFetched {
                source: "cloud-api".into()
            })
        );
        assert!(parse_anchor("operator:").is_err());
        assert!(parse_anchor("certificate").is_err());
    }

    #[test]
    fn no_tpm_is_unattested_with_its_reason() {
        let args = NodeEvidenceArgs {
            node_evidence_tpm: None,
            node_evidence_ak_template: "default-ecc".into(),
            node_evidence_anchor: "none".into(),
            node_evidence_epoch_secs: 300,
        };
        let dir = tempfile::tempdir().unwrap();
        let source = NodePlatformSource::start(&args, dir.path(), [1; 32], false).unwrap();
        assert!(matches!(
            source.platform(),
            NodePlatform::Unattested { reason } if reason.contains("--node-evidence-tpm")
        ));
    }

    #[test]
    fn an_unusable_tpm_is_a_startup_error_not_a_downgrade() {
        let dir = tempfile::tempdir().unwrap();
        let args = NodeEvidenceArgs {
            node_evidence_tpm: Some(dir.path().join("no-such-tpm")),
            node_evidence_ak_template: "default-ecc".into(),
            node_evidence_anchor: "none".into(),
            node_evidence_epoch_secs: 300,
        };
        assert!(NodePlatformSource::start(&args, dir.path(), [1; 32], false).is_err());
    }

    #[test]
    fn stored_documents_are_named_only_by_a_digest() {
        assert!(is_digest(&"ab".repeat(32)));
        assert!(!is_digest("../../etc/passwd"));
        assert!(!is_digest(&"AB".repeat(32)));
    }
}
