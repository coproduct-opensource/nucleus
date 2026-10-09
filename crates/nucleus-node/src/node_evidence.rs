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
//!
//! On a federating node with a TPM, the federation key itself lives in the
//! TPM, bound to the boot PCRs (ADR 0012), and every epoch the AK certifies
//! each published key (`TPM2_Certify`). The custody statements are stored
//! beside the evidence (`nucleus_federation::custody::KEY_ATTESTATION_STATE_FILE`,
//! and content-addressed in the store) and served at
//! `GET /v1/node/federation-keys`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use axum::Json;
use axum::extract::{Path as UrlPath, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use nucleus_ci_verdict::execution::NodePlatform;
use nucleus_federation::custody::KEY_ATTESTATION_STATE_FILE;
use nucleus_federation::keyring::{Held, KeyDir};
use nucleus_federation::{FileCustody, KeyCustody, TpmCustody, TpmEndpoint};
use nucleus_federation::{NodeAttestation, SelfAppraisal};
use nucleus_node_evidence::attester::{
    AkTemplate, Attester, DeviceTransport, LogSources, Tpm, default_pcrs,
};
use nucleus_node_evidence::{
    AkAnchorClaim, AnchorPolicy, AttestedKey, CustodyStatement, ExecutorKey, Federation,
    FederationKeyAttestation, Freshness, KEY_ATTESTATION_PROFILE, KeyBinding, Nonce, OperatorPin,
    ReferenceManifest, evidence_digest,
};
use tracing::{info, warn};

use crate::NodeState;
use crate::keys::{NODE_KEY_FILE_WAIVER_FLAG, NodeCustody, NodeKeyCustody, NodeKeyFileCustody};

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
    /// The anchor this node claims for its AK: `none`; `operator:<source>`
    /// naming where the operator fetched the AK from; or
    /// `software-tpm:<source>` for a SOFTWARE TPM (swtpm) the operator runs,
    /// which no hardware roots and every result labels so. A claim only; the
    /// relying party's own pin decides whether it anchors anything.
    #[arg(long, env = "NUCLEUS_NODE_EVIDENCE_ANCHOR", default_value = "none")]
    node_evidence_anchor: String,
    /// Seconds between epoch re-quotes.
    #[arg(long, env = "NUCLEUS_NODE_EVIDENCE_EPOCH_SECS", default_value_t = 300)]
    node_evidence_epoch_secs: u64,
    /// The reference manifest (`nucleus-node-reference/v1`) this node
    /// appraises its own evidence against, for the platform tier every
    /// federation assertion states (ADR 0012 A3). Unset: no appraisal, and
    /// every assertion states `unattested` while still naming the evidence.
    /// A flag only, never an env var: it decides what the node may claim.
    #[arg(long)]
    node_evidence_reference: Option<PathBuf>,
    /// SHA-256 (hex) of this node's AK SubjectPublicKeyInfo, as the operator
    /// fetched it from the source `--node-evidence-anchor` names
    /// (`operator:<source>` or `software-tpm:<source>`). The node's own
    /// appraisal anchors its AK only under this pin, as a relying party's
    /// would, and under the same kind: a software TPM's pin anchors only as a
    /// software TPM. Without it the tier is `unattested`. A flag only, never
    /// an env var.
    #[arg(long, requires = "node_evidence_reference")]
    node_evidence_ak_pin: Option<String>,
    /// Read the boot and IMA logs from this directory, laid out as
    /// securityfs is (`tpm0/binary_bios_measurements`,
    /// `ima/binary_runtime_measurements_sha256`), instead of
    /// `/sys/kernel/security`. Only with `--node-evidence-anchor
    /// software-tpm:<source>`: the kernel's logs record what the kernel's TPM
    /// measured, and a software TPM's measurements are the operator's, which
    /// is what its anchor says. A flag only, never an env var.
    #[arg(long)]
    node_evidence_logs: Option<PathBuf>,
    /// Keep the federation issuer key in a file although this node has a TPM
    /// (ADR 0012). Without it, a node with `--node-evidence-tpm` creates its
    /// federation key in the TPM, bound to the boot PCRs, so a copied disk
    /// cannot mint this issuer's credentials. With it, the key is a file, the
    /// waiver is logged at start-up, and every custody statement the node
    /// publishes says so. A flag only, never an env var: ambient
    /// configuration is not a waiver.
    #[arg(long = "allow-federation-key-in-file", action = clap::ArgAction::SetTrue)]
    allow_federation_key_in_file: bool,
    /// Keep the node's Ed25519 keys (executor, task issuer, approval,
    /// certificate root) in files although this node has a TPM (A2). Without
    /// it, a node with `--node-evidence-tpm` seals each key to the TPM under
    /// the boot PCRs, migrating an existing key file with its public key
    /// unchanged, so a copied disk holds no usable node key. With it, the keys
    /// stay files, the waiver is logged at start-up, and the node's key
    /// custody statement says so. A flag only, never an env var.
    #[arg(long = "allow-node-keys-in-file", action = clap::ArgAction::SetTrue)]
    allow_node_keys_in_file: bool,
    /// The anonymous, read-only evidence listener (`public_evidence`).
    #[command(flatten)]
    pub(crate) public: crate::public_evidence::PublicEvidenceArgs,
}

/// One custody decision from the TPM flag and a waiver: the truth table both
/// the federation key and the node keys follow, written once (ADR 0007 G-1).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Decided<'a> {
    /// A TPM is configured and not waived.
    Tpm(&'a PathBuf),
    /// A TPM is configured and the waiver is passed.
    Waived,
    /// No TPM is configured.
    NoTpm,
}

/// A TPM configured and not waived is TPM custody; there is no default that
/// picks a file (B-1).
///
/// # Errors
/// The waiver without a TPM: a waiver that waives nothing is a
/// misconfiguration, not a no-op (B-5).
fn decide<'a>(
    tpm: Option<&'a PathBuf>,
    waived: bool,
    flag: &str,
    what: &str,
) -> Result<Decided<'a>, String> {
    match (tpm, waived) {
        (Some(device), false) => Ok(Decided::Tpm(device)),
        (Some(_), true) => Ok(Decided::Waived),
        (None, false) => Ok(Decided::NoTpm),
        (None, true) => Err(format!(
            "{flag} waives TPM custody of {what}, but no TPM is configured \
             (--node-evidence-tpm is unset)"
        )),
    }
}

impl NodeEvidenceArgs {
    /// Where the federation issuer key lives, decided from the TPM flag and
    /// its waiver (ADR 0012).
    ///
    /// # Errors
    /// The waiver without a TPM (B-5).
    pub(crate) fn federation_key_custody(&self) -> Result<KeyCustody, String> {
        Ok(
            match decide(
                self.node_evidence_tpm.as_ref(),
                self.allow_federation_key_in_file,
                nucleus_federation::FILE_CUSTODY_WAIVER_FLAG,
                "the federation key",
            )? {
                Decided::Tpm(device) => {
                    KeyCustody::Tpm(TpmCustody::new(TpmEndpoint::Device(device.clone())))
                }
                Decided::Waived => KeyCustody::File(FileCustody::Waived),
                Decided::NoTpm => KeyCustody::File(FileCustody::NoTpmConfigured),
            },
        )
    }

    /// Where the node's Ed25519 role keys are held at rest, decided from the
    /// TPM flag and its own waiver (A2).
    ///
    /// # Errors
    /// The waiver without a TPM (B-5).
    pub(crate) fn node_key_custody(&self) -> Result<NodeKeyCustody, String> {
        Ok(
            match decide(
                self.node_evidence_tpm.as_ref(),
                self.allow_node_keys_in_file,
                NODE_KEY_FILE_WAIVER_FLAG,
                "the node keys",
            )? {
                Decided::Tpm(device) => NodeKeyCustody::Sealed(TpmEndpoint::Device(device.clone())),
                Decided::Waived => NodeKeyCustody::File(NodeKeyFileCustody::Waived),
                Decided::NoTpm => NodeKeyCustody::File(NodeKeyFileCustody::NoTpmConfigured),
            },
        )
    }

    /// Both decisions, as the node's start-up takes them. A waived node-key
    /// custody is logged here, once.
    ///
    /// # Errors
    /// Either waiver without a TPM (B-5).
    pub(crate) fn custody(&self) -> Result<NodeCustody, String> {
        let custody = NodeCustody {
            federation: self.federation_key_custody()?,
            node_keys: self.node_key_custody()?,
        };
        if custody.node_keys == NodeKeyCustody::File(NodeKeyFileCustody::Waived) {
            warn!(
                "{NODE_KEY_FILE_WAIVER_FLAG}: the node's Ed25519 keys are FILES on a node with a \
                 TPM; a copy of this disk holds the executor, approval, certificate-root and \
                 task-issuer keys. The node's key custody statement records the waiver"
            );
        }
        Ok(custody)
    }
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
    let source = |kind: &str, source: &str| {
        if source.is_empty() {
            Err(format!("--node-evidence-anchor {kind}: needs a source"))
        } else {
            Ok(source.to_string())
        }
    };
    match (s.strip_prefix("operator:"), s.strip_prefix("software-tpm:")) {
        (Some(rest), _) => Ok(AkAnchorClaim::OperatorFetched {
            source: source("operator:", rest)?,
        }),
        (None, Some(rest)) => Ok(AkAnchorClaim::SoftwareTpm {
            source: source("software-tpm:", rest)?,
        }),
        (None, None) if s == "none" => Ok(AkAnchorClaim::None),
        (None, None) => Err(format!(
            "--node-evidence-anchor {s:?}: expected `none`, `operator:<source>` or \
             `software-tpm:<source>`"
        )),
    }
}

/// Where this node reads its boot and IMA logs: securityfs, or the directory
/// a software TPM's measurer wrote, which only a software-TPM anchor may name
/// (a hardware TPM's logs are the kernel's, B-5).
fn log_sources(logs: Option<&PathBuf>, anchor: &AkAnchorClaim) -> Result<LogSources, String> {
    match (logs, anchor) {
        (None, _) => Ok(LogSources::linux()),
        (Some(root), AkAnchorClaim::SoftwareTpm { .. }) => Ok(LogSources::under(root)),
        (
            Some(_),
            AkAnchorClaim::None
            | AkAnchorClaim::OperatorFetched { .. }
            | AkAnchorClaim::CertificateChain { .. },
        ) => Err(
            "--node-evidence-logs needs --node-evidence-anchor software-tpm:<source>: \
             a log the operator wrote speaks only for a software TPM"
                .into(),
        ),
    }
}

/// What the node appraises its own evidence against (ADR 0012 A3): the
/// operator's reference manifest and AK anchors, read once at start-up.
pub(crate) struct OwnAppraisal {
    reference: ReferenceManifest,
    anchors: AnchorPolicy,
}

impl OwnAppraisal {
    /// From the flags. `None` when no reference is configured.
    ///
    /// # Errors
    /// An unreadable or unparsable reference; a pin that is not SHA-256 hex;
    /// a pin with no `operator:<source>` anchor to name its source (a pin
    /// that pins nothing is a misconfiguration, B-5).
    fn from_args(args: &NodeEvidenceArgs, anchor: &AkAnchorClaim) -> Result<Option<Self>, String> {
        let Some(path) = &args.node_evidence_reference else {
            return Ok(None);
        };
        let bytes = std::fs::read(path)
            .map_err(|e| format!("--node-evidence-reference {}: {e}", path.display()))?;
        let reference: ReferenceManifest = serde_json::from_slice(&bytes)
            .map_err(|e| format!("--node-evidence-reference {}: {e}", path.display()))?;
        let pin = |pin: &String, source: &String| {
            if is_digest(&pin.to_ascii_lowercase()) {
                Ok(vec![OperatorPin {
                    source: source.clone(),
                    ak_spki_sha256: pin.to_ascii_lowercase(),
                }])
            } else {
                Err(format!(
                    "--node-evidence-ak-pin {pin:?}: expected SHA-256 hex of the AK's SubjectPublicKeyInfo"
                ))
            }
        };
        // The pin goes in the list of the kind the anchor claims, so the node
        // labels its own AK exactly as a relying party holding the same pin
        // would (G-1): a software TPM never self-appraises as operator-fetched.
        let (operator_pins, software_tpm_pins) = match (&args.node_evidence_ak_pin, anchor) {
            (None, _) => (Vec::new(), Vec::new()),
            (Some(p), AkAnchorClaim::OperatorFetched { source }) => (pin(p, source)?, Vec::new()),
            (Some(p), AkAnchorClaim::SoftwareTpm { source }) => (Vec::new(), pin(p, source)?),
            (Some(_), AkAnchorClaim::None | AkAnchorClaim::CertificateChain { .. }) => {
                return Err(
                    "--node-evidence-ak-pin needs --node-evidence-anchor operator:<source> or \
                     software-tpm:<source>: a pin names the source the operator fetched the AK from"
                        .into(),
                );
            }
        };
        Ok(Some(Self {
            reference,
            anchors: AnchorPolicy {
                trust_roots: Vec::new(),
                operator_pins,
                software_tpm_pins,
            },
        }))
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
    /// The state dir holding the federation keyring and the key's custody,
    /// when federation is on.
    federation: Option<(PathBuf, KeyCustody)>,
    /// Custody statements already made, by `kid`: a certification of a key
    /// stays true for the key's life, so each is made once.
    certified: Mutex<BTreeMap<String, CustodyStatement>>,
    store: PathBuf,
    latest: RwLock<Epoch>,
    epoch_secs: u64,
    /// What the node appraises its own evidence against, if configured.
    own_appraisal: Option<OwnAppraisal>,
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

pub(crate) fn is_digest(s: &str) -> bool {
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
        let federation = match &self.federation {
            None => Federation::NotFederated,
            Some((dir, _)) => {
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
        // A custody statement that cannot be made leaves the last one in
        // place; it describes keys by kid, so it never says something false
        // about a key it names. A relying party missing a new kid gets
        // `Unstated`, never a pass.
        if let Err(e) = self.publish_key_attestation() {
            warn!(error = %e, "federation key custody statements not refreshed");
        }
        Ok(epoch)
    }

    /// Certify every published federation key with the AK, and store the
    /// statements beside the evidence (ADR 0012). A file key is stated as a
    /// file, with the reason.
    fn publish_key_attestation(&self) -> Result<(), String> {
        let Some((dir, custody)) = &self.federation else {
            return Ok(());
        };
        let now = u64::try_from(unix_now()?).map_err(|e| e.to_string())?;
        let published = KeyDir::new(dir)
            .published_custody(now)
            .map_err(|e| format!("federation keyring: {e}"))?;
        let mut certified = self
            .certified
            .lock()
            .map_err(|_| "custody cache lock poisoned".to_string())?;
        let mut keys = Vec::new();
        for (jwk, held) in published {
            let custody = match (held, custody) {
                (Held::Tpm(key), _) => match certified.get(&jwk.kid) {
                    Some(done) => done.clone(),
                    None => {
                        let mut attester = self
                            .attester
                            .lock()
                            .map_err(|_| "TPM attester lock poisoned".to_string())?;
                        let made = attester
                            .certify_federation_key(&key)
                            .map_err(|e| format!("certifying {}: {e}", jwk.kid))?;
                        certified.insert(jwk.kid.clone(), made.clone());
                        made
                    }
                },
                (Held::File, KeyCustody::File(why)) => CustodyStatement::File {
                    reason: why.reason(),
                },
                (Held::File, KeyCustody::Tpm(_)) => CustodyStatement::File {
                    reason: "a file key in a directory this node holds in TPM custody; \
                             the node refuses to sign with it"
                        .into(),
                },
            };
            keys.push(AttestedKey {
                kid: jwk.kid,
                custody,
            });
        }
        let doc = FederationKeyAttestation {
            profile: KEY_ATTESTATION_PROFILE.into(),
            keys,
        };
        let bytes = serde_json::to_vec_pretty(&doc).map_err(|e| e.to_string())?;
        let digest = hex::encode(evidence_digest(&bytes));
        write_atomic(&self.store.join(format!("{digest}.json")), &bytes)?;
        write_atomic(&dir.join(KEY_ATTESTATION_STATE_FILE), &bytes)
    }

    fn stored(&self, digest: &str) -> Option<Vec<u8>> {
        if !is_digest(digest) {
            return None;
        }
        std::fs::read(self.store.join(format!("{digest}.json"))).ok()
    }

    /// The node's appraisal of the evidence in force at `now` (ADR 0012 A3):
    /// the self-appraisal path every federation assertion's tier comes from.
    /// Re-run for each mint; the epoch document is read back from the store
    /// by the digest in force, so the tier is of the bytes a relying party
    /// fetches by the same digest.
    fn self_appraise(&self, now: u64) -> NodeAttestation {
        let digest = match self.latest.read() {
            Ok(e) => e.digest.clone(),
            Err(_) => return NodeAttestation::without_evidence("epoch state unavailable"),
        };
        let Some(document) = self.stored(&digest) else {
            return NodeAttestation::without_evidence(format!(
                "the evidence in force ({digest}) cannot be read from the store"
            ));
        };
        let Ok(now) = i64::try_from(now) else {
            return NodeAttestation::without_evidence("the clock is out of range");
        };
        let Some(own) = &self.own_appraisal else {
            return NodeAttestation::of_current_evidence(&document, None, now);
        };
        // The binding the node's quotes carry NOW: a quote taken before the
        // JWKS changed no longer speaks for the keys, so it is refused and the
        // tier is `unattested` until the next epoch.
        let binding = match self.binding() {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "own evidence not appraised: the binding cannot be read");
                return NodeAttestation::of_current_evidence(&document, None, now);
            }
        };
        NodeAttestation::of_current_evidence(
            &document,
            Some(&SelfAppraisal {
                binding: &binding,
                reference: &own.reference,
                anchors: &own.anchors,
                max_age_secs: SelfAppraisal::max_age_for_epoch(self.epoch_secs),
            }),
            now,
        )
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
            // A reference with no evidence to appraise configures nothing
            // (B-5); the pin `requires` the reference, so this covers both.
            // Nor does a log directory with no TPM to replay it against.
            if args.node_evidence_reference.is_some() || args.node_evidence_logs.is_some() {
                return Err("--node-evidence-reference and --node-evidence-logs need \
                     --node-evidence-tpm: there is no evidence to appraise without a TPM attester"
                    .into());
            }
            return Ok(Self::Unattested(
                "no TPM attester configured (--node-evidence-tpm is unset)".into(),
            ));
        };
        let template = parse_template(&args.node_evidence_ak_template)?;
        let anchor = parse_anchor(&args.node_evidence_anchor)?;
        let logs = log_sources(args.node_evidence_logs.as_ref(), &anchor)?;
        let own_appraisal = OwnAppraisal::from_args(args, &anchor)?;
        if federated && own_appraisal.is_none() {
            warn!(
                "federation issuer with a TPM but no --node-evidence-reference: every assertion \
                 states nucleus_att_tier=unattested (it still names the evidence epoch)"
            );
        }
        if args.node_evidence_epoch_secs == 0 {
            return Err("--node-evidence-epoch-secs must be positive".into());
        }
        let transport = DeviceTransport::open(device)
            .map_err(|e| format!("--node-evidence-tpm {}: {e}", device.display()))?;
        let federation = if federated {
            let custody = args.federation_key_custody()?;
            if custody == KeyCustody::File(FileCustody::Waived) {
                warn!(
                    "{}: the federation issuer key is a FILE on a node with a TPM; a copy \
                     of this disk can mint this issuer's credentials. Every custody statement \
                     this node publishes records the waiver",
                    nucleus_federation::FILE_CUSTODY_WAIVER_FLAG
                );
            }
            Some((state_dir.to_path_buf(), custody))
        } else {
            None
        };
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
                logs,
                anchor,
            )),
            executor_key,
            federation,
            certified: Mutex::new(BTreeMap::new()),
            store,
            latest: RwLock::new(Epoch {
                counter: previous,
                digest: String::new(),
            }),
            epoch_secs: args.node_evidence_epoch_secs,
            own_appraisal,
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

    /// Where stored evidence documents are, for the public listener: the
    /// store directory, or the reason this node has none.
    pub(crate) fn evidence_store(&self) -> Result<PathBuf, String> {
        match self {
            Self::Unattested(reason) => Err(reason.clone()),
            Self::Tpm(node) => Ok(node.store.clone()),
        }
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

impl crate::federated_credential::PlatformAttestation for NodePlatformSource {
    fn attestation_now(&self, now: u64) -> NodeAttestation {
        match self {
            Self::Unattested(reason) => NodeAttestation::without_evidence(reason.clone()),
            Self::Tpm(node) => node.self_appraise(now),
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

/// `GET /v1/node/federation-keys` — the custody statements of the published
/// federation keys (ADR 0012), as last stored.
async fn federation_keys(State(state): State<NodeState>) -> Response {
    match state.node_platform.as_ref() {
        NodePlatformSource::Unattested(reason) => unattested(reason),
        NodePlatformSource::Tpm(node) => match &node.federation {
            None => (
                StatusCode::NOT_FOUND,
                "this node is not a federation issuer",
            )
                .into_response(),
            Some((dir, _)) => match std::fs::read(dir.join(KEY_ATTESTATION_STATE_FILE)) {
                Ok(bytes) => evidence_response(bytes),
                Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
            },
        },
    }
}

/// `GET /v1/node/key-custody` — how the node's Ed25519 role keys are held at
/// rest (A2): sealed to the TPM under which boot policy, or a file and why.
/// The node's statement, as last recorded at start-up.
async fn key_custody(State(state): State<NodeState>) -> Response {
    match std::fs::read(
        state
            .state_dir
            .join(crate::keys::NODE_KEY_CUSTODY_STATE_FILE),
    ) {
        Ok(bytes) => evidence_response(bytes),
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
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

/// The evidence routes on the node's API listener. They skip the API's
/// authorization middleware — evidence is not secret — but that listener
/// still asks for a client certificate at the handshake. A relying party with
/// no node credential fetches documents from `public_evidence`, which does not
/// serve the challenge route (a quote costs TPM work).
pub(crate) fn routes() -> axum::Router<NodeState> {
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/v1/node/evidence", get(latest))
        .route("/v1/node/evidence/challenge", post(challenge))
        .route("/v1/node/federation-keys", get(federation_keys))
        .route("/v1/node/key-custody", get(key_custody))
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
        assert_eq!(
            parse_anchor("software-tpm:ci-swtpm"),
            Ok(AkAnchorClaim::SoftwareTpm {
                source: "ci-swtpm".into()
            })
        );
        assert!(parse_anchor("software-tpm:").is_err());
    }

    #[test]
    fn no_tpm_is_unattested_with_its_reason() {
        let args = NodeEvidenceArgs {
            node_evidence_tpm: None,
            node_evidence_ak_template: "default-ecc".into(),
            node_evidence_anchor: "none".into(),
            node_evidence_epoch_secs: 300,
            node_evidence_reference: None,
            node_evidence_ak_pin: None,
            node_evidence_logs: None,
            allow_federation_key_in_file: false,
            allow_node_keys_in_file: false,
            public: Default::default(),
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
            node_evidence_reference: None,
            node_evidence_ak_pin: None,
            node_evidence_logs: None,
            allow_federation_key_in_file: false,
            allow_node_keys_in_file: false,
            public: Default::default(),
        };
        assert!(NodePlatformSource::start(&args, dir.path(), [1; 32], false).is_err());
    }

    #[test]
    fn a_tpm_holds_the_federation_key_unless_waived_by_name() {
        let args = |tpm: Option<&str>, waived: bool| NodeEvidenceArgs {
            node_evidence_tpm: tpm.map(PathBuf::from),
            node_evidence_ak_template: "default-ecc".into(),
            node_evidence_anchor: "none".into(),
            node_evidence_epoch_secs: 300,
            node_evidence_reference: None,
            node_evidence_ak_pin: None,
            node_evidence_logs: None,
            allow_federation_key_in_file: waived,
            allow_node_keys_in_file: false,
            public: Default::default(),
        };
        assert_eq!(
            args(Some("/dev/tpmrm0"), false).federation_key_custody(),
            Ok(KeyCustody::Tpm(TpmCustody::new(TpmEndpoint::Device(
                "/dev/tpmrm0".into()
            ))))
        );
        assert_eq!(
            args(Some("/dev/tpmrm0"), true).federation_key_custody(),
            Ok(KeyCustody::File(FileCustody::Waived))
        );
        assert_eq!(
            args(None, false).federation_key_custody(),
            Ok(KeyCustody::File(FileCustody::NoTpmConfigured))
        );
        let err = args(None, true).federation_key_custody().unwrap_err();
        assert!(
            err.contains(nucleus_federation::FILE_CUSTODY_WAIVER_FLAG),
            "{err}"
        );
        // The waiver is a flag, never read from the environment.
        use clap::CommandFactory as _;
        #[derive(clap::Parser)]
        struct Cli {
            #[command(flatten)]
            a: NodeEvidenceArgs,
        }
        let cmd = Cli::command();
        let waiver = cmd
            .get_arguments()
            .find(|a| a.get_long() == Some("allow-federation-key-in-file"))
            .expect("the waiver flag exists");
        assert_eq!(waiver.get_env(), None);
    }

    /// A2: a node with a TPM seals its Ed25519 keys unless the operator
    /// passes the node keys' OWN waiver. The federation key's waiver does not
    /// waive it (the two decisions cost different things), and neither waiver
    /// is accepted without a TPM.
    #[test]
    fn a_tpm_seals_the_node_keys_unless_waived_by_their_own_name() {
        let args = |tpm: Option<&str>, fed_waived: bool, keys_waived: bool| NodeEvidenceArgs {
            node_evidence_tpm: tpm.map(PathBuf::from),
            node_evidence_ak_template: "default-ecc".into(),
            node_evidence_anchor: "none".into(),
            node_evidence_epoch_secs: 300,
            node_evidence_reference: None,
            node_evidence_ak_pin: None,
            node_evidence_logs: None,
            allow_federation_key_in_file: fed_waived,
            allow_node_keys_in_file: keys_waived,
            public: Default::default(),
        };
        let sealed = NodeKeyCustody::Sealed(TpmEndpoint::Device("/dev/tpmrm0".into()));
        assert_eq!(
            args(Some("/dev/tpmrm0"), false, false).node_key_custody(),
            Ok(sealed.clone())
        );
        // The federation waiver leaves the node keys sealed.
        let c = args(Some("/dev/tpmrm0"), true, false).custody().unwrap();
        assert_eq!(c.node_keys, sealed);
        assert_eq!(c.federation, KeyCustody::File(FileCustody::Waived));
        assert_eq!(
            args(Some("/dev/tpmrm0"), false, true).node_key_custody(),
            Ok(NodeKeyCustody::File(NodeKeyFileCustody::Waived))
        );
        assert_eq!(
            args(None, false, false).node_key_custody(),
            Ok(NodeKeyCustody::File(NodeKeyFileCustody::NoTpmConfigured))
        );
        let err = args(None, false, true).custody().unwrap_err();
        assert!(err.contains(NODE_KEY_FILE_WAIVER_FLAG), "{err}");
        use clap::CommandFactory as _;
        #[derive(clap::Parser)]
        struct Cli {
            #[command(flatten)]
            a: NodeEvidenceArgs,
        }
        let cmd = Cli::command();
        let waiver = cmd
            .get_arguments()
            .find(|a| a.get_long() == NODE_KEY_FILE_WAIVER_FLAG.strip_prefix("--"))
            .expect("the waiver flag exists, under the name the errors give");
        assert_eq!(waiver.get_env(), None);
    }
    /// A3: the inputs of the node's own appraisal are strict. A reference with
    /// no TPM, a pin with no operator anchor, and a pin that is not a digest
    /// are start-up errors, never an appraisal that silently differs; both
    /// flags are flags, never read from the environment.
    #[test]
    fn own_appraisal_inputs_are_strict() {
        let dir = tempfile::tempdir().unwrap();
        let reference = dir.path().join("reference.json");
        std::fs::copy(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../nucleus-node-evidence/tests/fixtures/live-node-reference-exact.json"
            ),
            &reference,
        )
        .unwrap();
        let args =
            |tpm: Option<&str>, reference: Option<&PathBuf>, pin: Option<&str>| NodeEvidenceArgs {
                node_evidence_tpm: tpm.map(PathBuf::from),
                node_evidence_ak_template: "default-ecc".into(),
                node_evidence_anchor: "none".into(),
                node_evidence_epoch_secs: 300,
                node_evidence_reference: reference.cloned(),
                node_evidence_ak_pin: pin.map(String::from),
                node_evidence_logs: None,
                allow_federation_key_in_file: false,
                allow_node_keys_in_file: false,
                public: Default::default(),
            };
        let pin = "BECED81752041938278ACD53C5DF51DF98652F58BB76BDF722E8965D25BD2366";
        let operator = AkAnchorClaim::OperatorFetched {
            source: "cloud-api:node-1".into(),
        };

        let err = NodePlatformSource::start(
            &args(None, Some(&reference), None),
            dir.path(),
            [1; 32],
            true,
        )
        .err()
        .expect("a reference without a TPM is refused");
        assert!(err.contains("--node-evidence-tpm"), "{err}");

        let own = OwnAppraisal::from_args(&args(None, Some(&reference), Some(pin)), &operator)
            .unwrap()
            .expect("configured");
        assert_eq!(
            own.anchors.operator_pins,
            vec![OperatorPin {
                source: "cloud-api:node-1".into(),
                ak_spki_sha256: pin.to_ascii_lowercase(),
            }]
        );
        assert!(own.anchors.trust_roots.is_empty());

        let err = OwnAppraisal::from_args(
            &args(None, Some(&reference), Some(pin)),
            &AkAnchorClaim::None,
        )
        .err()
        .expect("a pin with nothing to pin is refused");
        assert!(err.contains("operator:"), "{err}");
        assert!(
            OwnAppraisal::from_args(&args(None, Some(&reference), Some("zz")), &operator).is_err()
        );
        assert!(
            OwnAppraisal::from_args(
                &args(None, Some(&dir.path().join("absent")), None),
                &operator
            )
            .is_err()
        );
        assert!(
            OwnAppraisal::from_args(&args(None, None, None), &operator)
                .unwrap()
                .is_none()
        );

        use clap::CommandFactory as _;
        #[derive(clap::Parser)]
        struct Cli {
            #[command(flatten)]
            a: NodeEvidenceArgs,
        }
        // A software TPM's pin anchors only as a software TPM: the node never
        // labels its own swtpm AK operator-fetched.
        let software = AkAnchorClaim::SoftwareTpm {
            source: "ci-swtpm".into(),
        };
        let own = OwnAppraisal::from_args(&args(None, Some(&reference), Some(pin)), &software)
            .unwrap()
            .expect("configured");
        assert!(own.anchors.operator_pins.is_empty());
        assert_eq!(
            own.anchors.software_tpm_pins,
            vec![OperatorPin {
                source: "ci-swtpm".into(),
                ak_spki_sha256: pin.to_ascii_lowercase(),
            }]
        );

        let cmd = Cli::command();
        for flag in [
            "node-evidence-reference",
            "node-evidence-ak-pin",
            "node-evidence-logs",
        ] {
            let a = cmd
                .get_arguments()
                .find(|a| a.get_long() == Some(flag))
                .expect("the flag exists");
            assert_eq!(
                a.get_env(),
                None,
                "{flag} must not be read from the environment"
            );
        }
    }

    /// An operator-written log directory speaks only for a software TPM; on
    /// any other anchor it is a start-up error, never a log the node quotes.
    #[test]
    fn a_log_directory_is_accepted_only_for_a_software_tpm() {
        let root = PathBuf::from("/var/tmp/swtpm-logs");
        assert_eq!(
            log_sources(
                Some(&root),
                &AkAnchorClaim::SoftwareTpm {
                    source: "ci-swtpm".into()
                }
            )
            .map(|l| l.ima_sha256),
            Ok(root.join("ima/binary_runtime_measurements_sha256"))
        );
        for hardware in [
            AkAnchorClaim::None,
            AkAnchorClaim::OperatorFetched {
                source: "cloud-api".into(),
            },
            AkAnchorClaim::CertificateChain { chain: vec![] },
        ] {
            let err = log_sources(Some(&root), &hardware).unwrap_err();
            assert!(err.contains("software-tpm:"), "{err}");
        }
        assert_eq!(
            log_sources(None, &AkAnchorClaim::None).map(|l| l.ima_sha256),
            Ok(LogSources::linux().ima_sha256)
        );
    }

    /// A node with no TPM states `unattested`, naming no evidence, on every
    /// assertion it mints.
    #[test]
    fn no_tpm_states_unattested_on_assertions() {
        use crate::federated_credential::PlatformAttestation as _;
        let source = NodePlatformSource::Unattested("no TPM attester configured".into());
        let att = source.attestation_now(1_791_247_262);
        assert_eq!(att.tier(), nucleus_federation::ClaimedTier::Unattested);
        assert_eq!(att.evidence(), &nucleus_federation::EvidenceRef::NoEvidence);
    }

    #[test]
    fn stored_documents_are_named_only_by_a_digest() {
        assert!(is_digest(&"ab".repeat(32)));
        assert!(!is_digest("../../etc/passwd"));
        assert!(!is_digest(&"AB".repeat(32)));
    }
}
