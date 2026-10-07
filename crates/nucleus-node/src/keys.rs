//! The node's role-separated signing keys.
//!
//! Four persisted Ed25519 identities and one P-256 key, each a DISTINCT trust
//! role, and the shared load-or-create machinery behind them:
//!
//! | key | role |
//! |---|---|
//! | executor | the executor's receipt identity (`register_executor_pubkey`) |
//! | task issuer | signs live-path session capability tokens at pod spawn |
//! | approval | signs `/v1/approve`, verified in-guest by the tool proxy |
//! | certificate root | the anchor every pod's `LatticeCertificate` chains to |
//! | federation issuer (P-256) | signs the ES256 assertions a pod's upstream credential is exchanged for (ADR 0010) |
//!
//! # Why this is its own module (#2512)
//!
//! These lived in `trust_gate.rs`, a module whose stated subject was
//! "verifies agent attestations against the Coproduct Trust API and records
//! the resulting reputation". That file's own header had to carry a sentence
//! disclaiming the arrangement — "It also owns the node's role-separated
//! signing keys … which are unrelated to reputation" — which is a comment doing
//! a module boundary's job.
//!
//! The cost was concrete, not aesthetic: `pod_authority.rs` reaches into the
//! reputation module for `load_or_create_cert_root_signing_key`, the #2474
//! certificate root. So the file holding the node's most authority-bearing key
//! could not be deleted, and deleting the reputation code it was named for
//! required moving this first. Separation is what makes the removal possible.
//!
//! # What these keys are NOT
//!
//! None of them is a reputation input, and none decides what a pod may do. The
//! certificate-root key signs the certificate whose CONTENT decides authority;
//! it is the anchor, not the decision. Nothing here reads or writes a
//! `PodSpec`'s policy — `pod_authority::PodAuthority::admit` does that, once,
//! from the caller's certificate.
//!
//! # Custody at rest (A2, ADR 0012 addendum)
//!
//! On a node with a TPM (`--node-evidence-tpm`) the four Ed25519 keys are
//! SEALED to it: each 32-byte seed is a keyed-hash data object under the
//! TPM's storage primary whose `authPolicy` is `PolicyPCR` over the same boot
//! PCRs as the federation key's ([`nucleus_node_evidence::BOOT_POLICY_PCRS`]).
//! The disk holds the TPM's wrapping and the public area, nothing usable; the
//! node unseals each key into memory at start-up. A key file found on such a
//! node is MIGRATED: sealed, verified by unsealing what was written, and only
//! then deleted. The public key does not change, so every receipt, approval
//! and certificate it signed stays verifiable.
//!
//! What this does not do: the running node holds the unsealed keys in RAM,
//! so root on the running node can read them. The federation key, which the
//! TPM itself signs with, is the stronger case; Ed25519 cannot be that here,
//! because the TPMs this runs on do not implement it.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::{DecodePrivateKey as _, EncodePrivateKey as _};
use nucleus_node_evidence::key_attestation::boot_policy_pcrs;
use nucleus_node_evidence::tpm_key::{SealedBlob, TpmEndpoint, Zeroizing, seal, unseal};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

/// Filename (under `state_dir`) holding the persisted executor signing key.
const EXECUTOR_KEY_FILE: &str = "executor_signing_key.der";

/// Filename (under `state_dir`) holding the persisted **task-issuer** signing
/// key — the root that signs live-path session capability tokens. DISTINCT from
/// [`EXECUTOR_KEY_FILE`] so the two trust roles never share a key.
const TASK_ISSUER_KEY_FILE: &str = "task_issuer_signing_key.der";

/// Filename (under `state_dir`) holding the persisted **approval** signing
/// key — the key whose signatures the guest tool-proxy accepts on
/// `/v1/approve`, verified against the PUBLIC half delivered as
/// `nucleus.approval_pubkeys`. DISTINCT from the other two role keys: the
/// approval authority must not double as the executor's receipt identity or
/// the task-token root.
const APPROVAL_SIGNING_KEY_FILE: &str = "approval_signing_key.der";

/// Filename (under `state_dir`) holding the persisted **certificate-root**
/// signing key — the trust anchor every pod's `LatticeCertificate` chains
/// to (`pod_authority`). DISTINCT from the three role keys above: the
/// authority that says what a pod MAY do must not double as the executor's
/// receipt identity, the task-token root, or the approval authority.
const CERT_ROOT_KEY_FILE: &str = "cert_root_signing_key.der";

/// Filename (under `state_dir`) holding the persisted **federation issuer**
/// key: P-256, PKCS#8 DER, signing the ES256 assertions `federated_credential`
/// exchanges for upstream tokens.
///
/// A different CURVE from the four keys above, not only a different file,
/// because the relying parties are different: model providers' token endpoints
/// accept RSA or ECDSA and refuse EdDSA, so this issuer cannot share the
/// Ed25519 machinery — and must not share a key with any of those roles
/// regardless, since its signatures are presented OFF the node.
///
/// The name is `nucleus_federation::keyring`'s, not restated here: that module
/// owns this file and its rotation siblings (`.next.der`, `.prev.der`), and the
/// operator's `nucleus federation` CLI reads the same constant.
#[cfg(test)]
const JWT_SVID_P256_KEY_FILE: &str = nucleus_federation::keyring::CURRENT_KEY_FILE;

/// Generate a fresh Ed25519 signing key from the OS CSPRNG.
///
/// Samples 32 raw bytes via `rand_core 0.6`'s `fill_bytes` and feeds
/// `SigningKey::from_bytes` — equivalent to `SigningKey::generate(&mut rng)` but
/// avoids the cross-version `CryptoRng`/`rand_core` trait-identity mismatch that
/// breaks `generate` when multiple rand_core majors coexist (dalek 3 tracks a
/// newer rand_core than the 0.6 we depend on). Mirrors the pattern in
/// `nucleus-verifier-service::signing::VerifierSigner::random`.
pub(crate) fn generate_signing_key() -> SigningKey {
    use rand_core::RngCore as _;
    let mut seed = Zeroizing::new([0u8; 32]);
    rand_core::OsRng.fill_bytes(seed.as_mut_slice());
    SigningKey::from_bytes(&seed)
}

/// Load the per-executor Ed25519 signing key from `state_dir`, creating and
/// persisting a fresh one on first run.
///
/// Without persistence, every node restart mints a brand-new identity, which
/// silently invalidates any prior `register_executor_pubkey` enrollment — the
/// threat-model claim that registration survives an HMAC compromise is only
/// true if the executor's signing key is stable across restarts (#1630).
///
/// The key is stored as PKCS#8 DER (same encoding as
/// [`nucleus_lineage::LocalIssuer`]) with `0o400` permissions on Unix. A
/// missing file is created; a present-but-unreadable file is logged and
/// replaced rather than crashing the node (fail-open on *availability*, not on
/// identity — a corrupt key was never a valid enrollment anyway).
///
/// # Custody (A2)
///
/// Under [`NodeKeyCustody::Sealed`] the disk holds the key only sealed to the
/// TPM; see [`load_or_create_role_key`] for the whole contract.
///
/// # Errors
/// As [`load_or_create_role_key`].
pub fn load_or_create_signing_key(
    state_dir: &Path,
    custody: &NodeKeyCustody,
) -> Result<SigningKey, String> {
    load_or_create_role_key(state_dir, NodeKeyRole::Executor, custody)
}

/// Load the dedicated **task-issuer** Ed25519 signing key from `state_dir`,
/// creating and persisting a fresh one on first run.
///
/// Uses the identical persistence discipline as
/// [`load_or_create_signing_key`] (PKCS#8 DER, `0o400`, fail-open on
/// availability) but a DISTINCT file ([`TASK_ISSUER_KEY_FILE`]). This is the
/// root that signs live-path session capability tokens; keeping it separate
/// from the executor key enforces role separation — a compromise or rotation
/// of one identity does not implicate the other, and the executor key (which
/// is also the executor's receipt identity) never doubles as a token root.
///
/// # Errors
/// As [`load_or_create_role_key`].
pub fn load_or_create_task_issuer_signing_key(
    state_dir: &Path,
    custody: &NodeKeyCustody,
) -> Result<SigningKey, String> {
    load_or_create_role_key(state_dir, NodeKeyRole::TaskIssuer, custody)
}

/// Load the dedicated **approval** Ed25519 signing key from `state_dir`,
/// creating and persisting a fresh one on first run.
///
/// Same persistence discipline as the other role keys, and persistence
/// matters MORE here: a running pod verifies approvals against the public key
/// it booted with, so a node that minted a fresh key on every restart could
/// no longer approve anything for pods launched before the restart.
///
/// # Errors
/// As [`load_or_create_role_key`].
pub fn load_or_create_approval_signing_key(
    state_dir: &Path,
    custody: &NodeKeyCustody,
) -> Result<SigningKey, String> {
    load_or_create_role_key(state_dir, NodeKeyRole::Approval, custody)
}

/// Load the dedicated **certificate-root** Ed25519 signing key from
/// `state_dir`, creating and persisting a fresh one on first run.
///
/// Persistence is load-bearing: every running pod's certificate chains to
/// this key, and a pod's sub-pod requests are verified against it, so a node
/// that minted a fresh root on every restart would orphan every chain it had
/// issued.
///
/// # Errors
/// As [`load_or_create_role_key`].
pub fn load_or_create_cert_root_signing_key(
    state_dir: &Path,
    custody: &NodeKeyCustody,
) -> Result<SigningKey, String> {
    load_or_create_role_key(state_dir, NodeKeyRole::CertRoot, custody)
}

/// Load the **federation issuer** P-256 key from `state_dir`, creating and
/// persisting a fresh one on first run, as a signer that follows rotation.
///
/// Persistence is what keeps the `kid` stable: upstreams register this
/// issuer's JWKS, some of them inline, so a node that minted a new key per
/// restart would be refused by every such upstream until someone re-registered
/// it. A present-but-unparseable key is logged and replaced, as for the
/// Ed25519 role keys, with the cost stated in the warning.
///
/// # Rotation, and why no restart is needed
///
/// The returned [`KeyDirSigner`] signs with whatever key is in the current
/// file at the moment of each assertion, reloading it when an operator's
/// `nucleus federation rotate --promote` renames the staged key into place.
/// It never reads the staged (`next`) key. See `nucleus_federation::keyring`.
///
/// # Errors
/// * the key cannot be generated, or cannot be PERSISTED. P3 treated a
///   persist failure as a warning; with rotation it is fatal, because the JWKS
///   an operator publishes (`nucleus federation issuer --jwks`) is read from
///   this file — a key that exists only in memory is a key no provider can
///   ever be told about.
/// * the file exists with group/other permission bits, a foreign owner, or as
///   a symlink. That key may have been read by someone else; the node refuses
///   to sign with it rather than regenerate over the evidence.
///
/// # Custody (ADR 0012)
///
/// `custody` is decided once from the node's flags
/// (`NodeEvidenceArgs::federation_key_custody`). With a TPM it is created in
/// the TPM, bound to the boot PCRs, and the state directory holds only the
/// TPM's wrapping of it. A TPM key bound to ANOTHER boot state (the node was
/// upgraded, or booted with another command line) can never sign here, so it
/// is replaced like an unreadable file, with the same warning. A directory of
/// the other custody is refused, never converted: changing where the key
/// lives changes the key, and upstreams must be told.
pub fn load_or_create_jwt_svid_signing_key(
    state_dir: &Path,
    custody: &nucleus_federation::KeyCustody,
) -> Result<nucleus_federation::keyring::KeyDirSigner, String> {
    use nucleus_federation::KeyCustody;
    use nucleus_federation::keyring::{KeyDir, KeyDirSigner, KeyringError, StoredKey};
    let label = "federation issuer signing key";
    let keys = KeyDir::new(state_dir);
    let replace = |why: &dyn std::fmt::Display| -> Result<(), String> {
        warn!(
            reason = %why,
            "{label} cannot be used; regenerating — every upstream that registered \
             the old key (by kid) will refuse this node's assertions until updated"
        );
        keys.create_current(custody)
            .map(|_| ())
            .map_err(|e| format!("{label}: {e}"))
    };

    match (keys.load_current(), custody) {
        (Ok(Some(StoredKey::Tpm(key, jwk))), KeyCustody::Tpm(tpm)) => {
            if tpm.usable_now(&key).map_err(|e| format!("{label}: {e}"))? {
                debug!(dir = %state_dir.display(), kid = %jwk.kid, "loaded TPM-resident {label}");
            } else {
                replace(&format!(
                    "the TPM-resident key {} is bound to another boot state",
                    jwk.kid
                ))?;
            }
        }
        (Ok(Some(_)), _) => debug!(dir = %state_dir.display(), "loaded persisted {label}"),
        (Ok(None), _) => {
            keys.create_current(custody)
                .map_err(|e| format!("{label}: {e}"))?;
            info!(dir = %state_dir.display(), custody = %custody.kind(), "generated and persisted new {label}");
        }
        (Err(e @ KeyringError::Key { .. }), _) => replace(&e)?,
        (Err(e), _) => return Err(format!("{label}: {e}")),
    }
    KeyDirSigner::open(keys, custody.clone()).map_err(|e| format!("{label}: {e}"))
}

// ── Custody of the Ed25519 role keys (A2) ────────────────────────────────────

/// Which of the four persisted Ed25519 role keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKeyRole {
    /// The executor's receipt identity.
    Executor,
    /// The root of live-path session capability tokens.
    TaskIssuer,
    /// The key the guest tool proxy accepts approvals under.
    Approval,
    /// The anchor every pod's `LatticeCertificate` chains to.
    CertRoot,
}

impl NodeKeyRole {
    /// The PKCS#8 file this role's key is kept in under file custody, and the
    /// file a migration reads.
    fn file(self) -> &'static str {
        match self {
            Self::Executor => EXECUTOR_KEY_FILE,
            Self::TaskIssuer => TASK_ISSUER_KEY_FILE,
            Self::Approval => APPROVAL_SIGNING_KEY_FILE,
            Self::CertRoot => CERT_ROOT_KEY_FILE,
        }
    }

    /// The sealed blob's file, derived from [`Self::file`] (F-1: one name).
    fn sealed_file(self) -> String {
        format!("{}.sealed.json", self.file().trim_end_matches(".der"))
    }

    /// For log lines and errors.
    fn label(self) -> &'static str {
        match self {
            Self::Executor => "executor signing key",
            Self::TaskIssuer => "task issuer signing key",
            Self::Approval => "approval signing key",
            Self::CertRoot => "certificate root signing key",
        }
    }
}

/// Where the node's Ed25519 role keys are held at rest. Decided once from the
/// node's flags (`NodeEvidenceArgs::custody`, G-1); there is no `Default`
/// (B-1), and no `Option` whose `None` means "a file" (B-2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeKeyCustody {
    /// Sealed to the TPM at this endpoint, under `PolicyPCR` over the boot
    /// PCRs, and unsealed into memory at start-up.
    Sealed(TpmEndpoint),
    /// `0400` PKCS#8 files, for the stated reason.
    File(NodeKeyFileCustody),
}

/// Why the node's Ed25519 keys are files. Recorded in the node's key custody
/// statement, so a reader sees the reason beside "file".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKeyFileCustody {
    /// The node has no TPM configured.
    NoTpmConfigured,
    /// The node has a TPM, and the operator waived sealing with
    /// [`NODE_KEY_FILE_WAIVER_FLAG`].
    Waived,
}

/// The node flag that keeps the Ed25519 role keys in files on a node with a
/// TPM. Its own flag, not the federation key's waiver: the two decisions cost
/// different things. Moving the federation key into the TPM makes a NEW key
/// that every upstream must be told about, so an operator may reasonably defer
/// it; sealing the node keys keeps every public key, so it costs nothing to
/// take. One waiver for both would force the cheap protection to wait on the
/// expensive one. A flag only, never an env var: ambient configuration is not a
/// waiver.
pub const NODE_KEY_FILE_WAIVER_FLAG: &str = "--allow-node-keys-in-file";

impl NodeKeyFileCustody {
    /// The reason, as recorded.
    pub fn reason(self) -> String {
        match self {
            Self::NoTpmConfigured => "no TPM is configured on this node".into(),
            Self::Waived => format!(
                "the node has a TPM, and its operator waived sealing the node keys \
                 ({NODE_KEY_FILE_WAIVER_FLAG})"
            ),
        }
    }
}

/// Both custody decisions a node makes about its keys at start-up: the
/// federation issuer key's (ADR 0012) and the Ed25519 role keys' (A2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeCustody {
    /// The federation issuer key.
    pub federation: nucleus_federation::KeyCustody,
    /// The four Ed25519 role keys.
    pub node_keys: NodeKeyCustody,
}

/// The profile of a sealed key file.
const SEALED_KEY_PROFILE: &str = "nucleus-tpm-sealed-key/v1";

/// How a sealed key came to be sealed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SealOrigin {
    /// The node generated it and sealed it at once; no file ever held it.
    Generated,
    /// It was a key file, sealed with the same public key, and the file was
    /// deleted once the sealed blob unsealed to it.
    MigratedFromFile,
}

/// A sealed key file: the TPM's bytes, base64, the policy's PCRs, and the
/// public key the sealed seed must produce.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedKeyFile {
    profile: String,
    role: NodeKeyRole,
    /// The Ed25519 public key, hex.
    public_key: String,
    /// `TPM2B_PUBLIC`, base64.
    public: String,
    /// `TPM2B_PRIVATE`, base64.
    private: String,
    policy_pcrs: BTreeSet<u8>,
    origin: SealOrigin,
    /// Unix seconds.
    sealed_at: u64,
}

impl SealedKeyFile {
    fn blob(&self) -> Result<SealedBlob, String> {
        if self.profile != SEALED_KEY_PROFILE {
            return Err(format!("unknown sealed-key profile {:?}", self.profile));
        }
        let public = STANDARD.decode(&self.public).map_err(|e| e.to_string())?;
        let private = STANDARD.decode(&self.private).map_err(|e| e.to_string())?;
        SealedBlob::from_parts(public, private, self.policy_pcrs.clone()).map_err(|e| e.to_string())
    }

    fn record(&self, blob: &SealedBlob) -> CustodyRecord {
        CustodyRecord::TpmSealed {
            public: self.public.clone(),
            policy_pcrs: self.policy_pcrs.clone(),
            policy_digest: hex::encode(blob.auth_policy()),
            origin: self.origin,
            sealed_at: self.sealed_at,
        }
    }
}

/// How one role key is held, as the node states it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyRecord {
    /// Sealed to the TPM. `public` is the sealed object's `TPM2B_PUBLIC`
    /// (base64), whose `authPolicy` is `policy_digest`: `PolicyPCR` over
    /// `policy_pcrs` at the values they held when it was sealed, so a reader
    /// holding a quote of those PCRs can recompute it.
    TpmSealed {
        /// `TPM2B_PUBLIC`, base64.
        public: String,
        /// The PCRs the policy selects.
        policy_pcrs: BTreeSet<u8>,
        /// The `authPolicy`, hex.
        policy_digest: String,
        /// Generated sealed, or migrated from a file.
        origin: SealOrigin,
        /// Unix seconds.
        sealed_at: u64,
    },
    /// A file, for the reason given.
    File {
        /// Why.
        reason: String,
    },
}

/// The profile of the node's key custody statement.
pub const NODE_KEY_CUSTODY_PROFILE: &str = "nucleus-node-key-custody/v1";

/// Where the node keeps its key custody statement, relative to its state
/// directory: beside the evidence documents and the federation keys'
/// statements. Served at `GET /v1/node/key-custody`.
pub const NODE_KEY_CUSTODY_STATE_FILE: &str = "node-evidence/node-keys.json";

/// One role key's entry in the statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeKeyStatement {
    /// Which key.
    pub role: NodeKeyRole,
    /// The Ed25519 public key, hex.
    pub public_key: String,
    /// How it is held.
    pub custody: CustodyRecord,
}

/// The node's key custody statement. Asserted by the node: the sealed
/// objects are not (yet) certified by the AK, so a reader learns what the node
/// says, and can check `policy_digest` against a quote of `policy_pcrs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeKeyCustodyStatement {
    /// [`NODE_KEY_CUSTODY_PROFILE`].
    pub profile: String,
    /// One entry per role key loaded, in role order.
    pub keys: Vec<NodeKeyStatement>,
}

/// Serialises read-modify-write of the statement within this process.
static STATEMENT: Mutex<()> = Mutex::new(());

/// Record `role`'s custody in the statement, replacing any earlier entry.
fn record_custody(
    state_dir: &Path,
    role: NodeKeyRole,
    key: &SigningKey,
    custody: CustodyRecord,
) -> Result<(), String> {
    let _guard = STATEMENT
        .lock()
        .map_err(|_| "key custody statement lock poisoned".to_string())?;
    let path = state_dir.join(NODE_KEY_CUSTODY_STATE_FILE);
    let mut doc = match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice::<NodeKeyCustodyStatement>(&bytes)
            .ok()
            .filter(|d| d.profile == NODE_KEY_CUSTODY_PROFILE)
            .unwrap_or_else(|| NodeKeyCustodyStatement {
                profile: NODE_KEY_CUSTODY_PROFILE.into(),
                keys: Vec::new(),
            }),
        Err(_) => NodeKeyCustodyStatement {
            profile: NODE_KEY_CUSTODY_PROFILE.into(),
            keys: Vec::new(),
        },
    };
    doc.keys.retain(|k| k.role != role);
    doc.keys.push(NodeKeyStatement {
        role,
        public_key: hex::encode(key.verifying_key().as_bytes()),
        custody,
    });
    doc.keys.sort_by_key(|k| k.role);
    let bytes = serde_json::to_vec_pretty(&doc).map_err(|e| e.to_string())?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    }
    write_atomic(&path, &bytes, 0o644)
}

/// Load `role`'s key under `custody`, creating it on first run.
///
/// # File custody
///
/// The PKCS#8 file, as before A2: a missing file is created, an unreadable one
/// is logged and replaced. A SEALED key in the directory is refused: the file
/// layout cannot read it, and the custody is never crossed by regenerating
/// over it.
///
/// # Sealed custody
///
/// * A sealed key unseals into memory. If the key file is ALSO present, a
///   migration was interrupted after the sealed blob was written: the file is
///   deleted if it holds the same key, and the node refuses to start if it
///   holds a different one.
/// * A sealed key the TPM refuses for its policy (the boot changed: kernel,
///   initrd, boot loader, command line, Secure Boot state) or its integrity
///   (another TPM sealed it) is set aside, kept beside under an
///   `.unusable-<time>` name, and replaced, with a warning. Any other TPM
///   failure stops the node: it is not a reason to change identity.
/// * A key file and no usable sealed key is a MIGRATION: the key is sealed,
///   the sealed blob is written atomically, read back and unsealed, and only
///   when it unseals to the same key is the file deleted. A crash at any point
///   leaves either the file or the sealed blob, and the next start completes it.
/// * Neither: a new key, sealed, verified the same way.
///
/// A TPM that cannot be reached or refuses to seal stops the node: a node
/// configured to seal its keys does not run on a file key unless the operator
/// passes [`NODE_KEY_FILE_WAIVER_FLAG`].
///
/// Either way the outcome is logged and recorded in the node's key custody
/// statement ([`NODE_KEY_CUSTODY_STATE_FILE`]).
///
/// # Errors
/// As above; the message names the key and, for a TPM failure, the waiver.
pub fn load_or_create_role_key(
    state_dir: &Path,
    role: NodeKeyRole,
    custody: &NodeKeyCustody,
) -> Result<SigningKey, String> {
    let label = role.label();
    let (key, record) = match custody {
        NodeKeyCustody::File(why) => {
            let sealed = state_dir.join(role.sealed_file());
            if sealed.exists() {
                return Err(format!(
                    "{label}: {} holds the key sealed to a TPM, and this node keeps its keys \
                     in files ({}). The custody is never crossed: configure the TPM it was \
                     sealed to (--node-evidence-tpm) without {NODE_KEY_FILE_WAIVER_FLAG}",
                    sealed.display(),
                    why.reason()
                ));
            }
            let key = load_or_create_key_file(state_dir, role.file(), label);
            (
                key,
                CustodyRecord::File {
                    reason: why.reason(),
                },
            )
        }
        NodeKeyCustody::Sealed(endpoint) => load_or_create_sealed(state_dir, role, endpoint)?,
    };
    if let Err(e) = record_custody(state_dir, role, &key, record) {
        warn!(error = %e, "{label}: key custody statement not recorded");
    }
    Ok(key)
}

/// A TPM failure under sealed custody, naming the waiver.
fn tpm_failure(label: &str, endpoint: &TpmEndpoint, e: &dyn fmt::Display) -> String {
    format!(
        "{label}: TPM {endpoint}: {e}. This node seals its keys to the TPM and does not \
         fall back to a key file; to keep the keys in files on a node with a TPM, pass \
         {NODE_KEY_FILE_WAIVER_FLAG}"
    )
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn read_sealed(path: &Path) -> Result<(SealedKeyFile, SealedBlob), String> {
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    let file: SealedKeyFile = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let blob = file.blob()?;
    Ok((file, blob))
}

/// The key a 32-byte unsealed seed is.
fn key_from_seed(seed: &[u8]) -> Result<SigningKey, String> {
    let seed = Zeroizing::new(
        <[u8; 32]>::try_from(seed)
            .map_err(|_| format!("the sealed secret is {} bytes, not 32", seed.len()))?,
    );
    Ok(SigningKey::from_bytes(&seed))
}

/// The key a PKCS#8 file holds, or `None` when there is no file or it does
/// not parse (logged; the caller makes a new key).
fn read_key_file(path: &Path, label: &str) -> Option<SigningKey> {
    let bytes = match std::fs::read(path) {
        Ok(b) => Zeroizing::new(b),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            warn!(path = %path.display(), error = %e, "failed to read {label} file; a new key is made");
            return None;
        }
    };
    match SigningKey::from_pkcs8_der(&bytes) {
        Ok(key) => Some(key),
        Err(e) => {
            warn!(path = %path.display(), error = %e, "{label} file is unreadable; a new key is made");
            None
        }
    }
}

fn load_or_create_sealed(
    state_dir: &Path,
    role: NodeKeyRole,
    endpoint: &TpmEndpoint,
) -> Result<(SigningKey, CustodyRecord), String> {
    let label = role.label();
    let plain = state_dir.join(role.file());
    let sealed = state_dir.join(role.sealed_file());

    if sealed.exists() {
        match read_sealed(&sealed) {
            Err(e) => set_aside(
                &sealed,
                label,
                &format!("the sealed key file is unreadable: {e}"),
            )?,
            Ok((file, blob)) => {
                let mut tpm = endpoint
                    .connect()
                    .map_err(|e| tpm_failure(label, endpoint, &e))?;
                match unseal(&mut tpm, &blob) {
                    Ok(seed) => {
                        let key = key_from_seed(&seed)?;
                        if hex::encode(key.verifying_key().as_bytes()) != file.public_key {
                            return Err(format!(
                                "{label}: the key sealed in {} is not the public key recorded \
                                 beside it; refusing to guess which is this node's",
                                sealed.display()
                            ));
                        }
                        if plain.exists() {
                            finish_interrupted_migration(&plain, &key, label)?;
                        }
                        debug!(path = %sealed.display(), "unsealed {label}");
                        return Ok((key, file.record(&blob)));
                    }
                    Err(e) if e.is_policy_failure() => set_aside(
                        &sealed,
                        label,
                        "it is sealed to another boot state (a policy PCR moved: the kernel, \
                         initrd, boot loader, command line or Secure Boot state changed)",
                    )?,
                    Err(e) if e.is_integrity_failure() => {
                        set_aside(&sealed, label, "it was sealed by another TPM")?;
                    }
                    Err(e) => return Err(tpm_failure(label, endpoint, &e)),
                }
            }
        }
    }

    // No usable sealed key: migrate the file key, or make a new one.
    let (key, origin) = match read_key_file(&plain, label) {
        Some(key) => (key, SealOrigin::MigratedFromFile),
        None => (generate_signing_key(), SealOrigin::Generated),
    };
    let record = seal_and_verify(endpoint, &sealed, role, &key, origin)?;
    if plain.exists() {
        remove_durably(&plain).map_err(|e| {
            format!(
                "{label}: sealed and verified, but the key file {} was not removed: {e}",
                plain.display()
            )
        })?;
    }
    match origin {
        SealOrigin::MigratedFromFile => info!(
            sealed = %sealed.display(),
            public_key = %hex::encode(key.verifying_key().as_bytes()),
            "migrated {label} into TPM custody: sealed to the boot PCRs with the SAME public key; \
             the key file is deleted"
        ),
        SealOrigin::Generated => info!(
            sealed = %sealed.display(),
            "generated {label} and sealed it to the TPM"
        ),
    }
    Ok((key, record))
}

/// Seal `key` to the boot PCRs, write the blob to `path` atomically, then read
/// it back from disk and unseal it: the blob is accepted only when what is on
/// disk unseals to this key. On any failure the blob just written is removed,
/// so it never stands beside a file key it does not match.
fn seal_and_verify(
    endpoint: &TpmEndpoint,
    path: &Path,
    role: NodeKeyRole,
    key: &SigningKey,
    origin: SealOrigin,
) -> Result<CustodyRecord, String> {
    let label = role.label();
    let seed = Zeroizing::new(key.to_bytes());
    let public_key = hex::encode(key.verifying_key().as_bytes());
    let mut tpm = endpoint
        .connect()
        .map_err(|e| tpm_failure(label, endpoint, &e))?;
    let blob = seal(&mut tpm, &boot_policy_pcrs(), seed.as_slice())
        .map_err(|e| tpm_failure(label, endpoint, &e))?;
    let file = SealedKeyFile {
        profile: SEALED_KEY_PROFILE.into(),
        role,
        public_key: public_key.clone(),
        public: STANDARD.encode(blob.public()),
        private: STANDARD.encode(blob.private()),
        policy_pcrs: blob.policy_pcrs().clone(),
        origin,
        sealed_at: unix_now(),
    };
    let bytes = serde_json::to_vec_pretty(&file).map_err(|e| format!("{label}: {e}"))?;
    write_atomic(path, &bytes, 0o400).map_err(|e| format!("{label}: {e}"))?;
    #[cfg(test)]
    if let Some(hook) = tests::BEFORE_VERIFY.with(std::cell::Cell::get) {
        hook(path);
    }
    let verified = (|| -> Result<CustodyRecord, String> {
        let (stored, stored_blob) = read_sealed(path)?;
        let back = unseal(&mut tpm, &stored_blob).map_err(|e| e.to_string())?;
        if back.as_slice() != seed.as_slice() || stored.public_key != public_key {
            return Err(
                "the sealed blob on disk does not unseal to the key it was made from".into(),
            );
        }
        Ok(stored.record(&stored_blob))
    })();
    verified.map_err(|e| {
        let _ = std::fs::remove_file(path);
        tpm_failure(label, endpoint, &format!("sealing did not round-trip: {e}"))
    })
}

/// A key file beside a sealed key that unsealed: a migration stopped between
/// writing the blob and deleting the file. The same key: delete the file. A
/// different key: refuse, rather than pick one identity silently.
fn finish_interrupted_migration(plain: &Path, key: &SigningKey, label: &str) -> Result<(), String> {
    if let Some(file_key) = read_key_file(plain, label)
        && file_key.verifying_key() != key.verifying_key()
    {
        return Err(format!(
            "{label}: {} holds a DIFFERENT key from the sealed one; refusing to choose. \
             Move one of them aside",
            plain.display()
        ));
    }
    remove_durably(plain).map_err(|e| format!("{label}: removing {}: {e}", plain.display()))?;
    info!(
        path = %plain.display(),
        "{label}: completed an interrupted migration into TPM custody; the key file is deleted"
    );
    Ok(())
}

/// Move an unusable sealed key aside, keeping it: booting back into the state
/// it was sealed in and moving it back recovers it.
fn set_aside(sealed: &Path, label: &str, why: &str) -> Result<(), String> {
    let mut aside = sealed.as_os_str().to_owned();
    aside.push(format!(".unusable-{}", unix_now()));
    let aside = PathBuf::from(aside);
    std::fs::rename(sealed, &aside)
        .map_err(|e| format!("{label}: {why}, and it could not be moved aside: {e}",))?;
    warn!(
        kept = %aside.display(),
        "{label} cannot be unsealed: {why}. A NEW key replaces it — receipts, approvals and \
         certificates under the old public key stay verifiable, but anything that registered \
         or pinned the old key must be told the new one"
    );
    Ok(())
}

/// Remove `path` and make the removal durable.
fn remove_durably(path: &Path) -> std::io::Result<()> {
    std::fs::remove_file(path)?;
    sync_parent(path)
}

/// `fsync` the directory holding `path`, so a rename or removal in it survives
/// a crash.
fn sync_parent(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        std::fs::File::open(dir)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Write `bytes` to `path` atomically: a temporary file in the same
/// directory, written and synced, renamed over `path`, the directory synced,
/// and the final permissions `mode`. A crash leaves the old `path` or the new
/// one, never a torn file.
fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    use std::io::Write as _;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    match std::fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("removing {}: {e}", tmp.display())),
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let written = options.open(&tmp).and_then(|mut f| {
        f.write_all(bytes)?;
        f.sync_all()
    });
    written.map_err(|e| format!("writing {}: {e}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))
            .map_err(|e| format!("setting the mode of {}: {e}", tmp.display()))?;
    }
    #[cfg(not(unix))]
    let _ = mode;
    std::fs::rename(&tmp, path).map_err(|e| format!("renaming {}: {e}", tmp.display()))?;
    sync_parent(path).map_err(|e| format!("syncing the directory of {}: {e}", path.display()))
}

/// Shared implementation for the persisted per-node Ed25519 keys. `filename` is
/// the basename under `state_dir`; `label` is used only in log lines.
fn load_or_create_key_file(state_dir: &Path, filename: &str, label: &str) -> SigningKey {
    let path = state_dir.join(filename);

    if path.exists() {
        match std::fs::read(&path) {
            Ok(bytes) => match SigningKey::from_pkcs8_der(&bytes) {
                Ok(key) => {
                    debug!(path = %path.display(), "loaded persisted {label}");
                    return key;
                }
                Err(e) => warn!(
                    path = %path.display(),
                    error = %e,
                    "{label} file is unreadable; regenerating"
                ),
            },
            Err(e) => warn!(
                path = %path.display(),
                error = %e,
                "failed to read {label} file; regenerating"
            ),
        }
    }

    let key = generate_signing_key();
    match key.to_pkcs8_der() {
        Ok(der) => {
            if let Err(e) = write_key_file(&path, der.as_bytes()) {
                warn!(
                    path = %path.display(),
                    error = %e,
                    "failed to persist {label}; identity will not survive restart"
                );
            } else {
                info!(path = %path.display(), "generated and persisted new {label}");
            }
        }
        Err(e) => warn!(error = %e, "failed to PKCS#8-encode {label}; not persisting"),
    }
    key
}

/// Write `bytes` to `path`, restricting permissions to owner-read-only (`0o400`)
/// on Unix so the private key is not world/group readable.
fn write_key_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// File custody on a node with no TPM: the layout before A2.
    const FILE: NodeKeyCustody = NodeKeyCustody::File(NodeKeyFileCustody::NoTpmConfigured);

    // ── Executor signing-key persistence (#1630) ──────────────────────────

    #[test]
    fn test_signing_key_persists_across_calls() {
        // The core property: a "restart" (a second load from the same
        // state_dir) must yield the SAME executor identity.
        let dir = tempfile::tempdir().unwrap();
        let k1 = load_or_create_signing_key(dir.path(), &FILE).unwrap();
        let k2 = load_or_create_signing_key(dir.path(), &FILE).unwrap();
        assert_eq!(
            k1.verifying_key().as_bytes(),
            k2.verifying_key().as_bytes(),
            "executor signing key must be stable across restarts"
        );
        assert!(dir.path().join(EXECUTOR_KEY_FILE).exists());
    }

    /// Role separation: the task-issuer key must be a DIFFERENT key from the
    /// executor key in the same state_dir (distinct files), yet each must be
    /// stable across restarts. Reusing the executor key as the token root would
    /// conflate the executor identity with the capability-token issuer.
    #[test]
    fn test_task_issuer_key_is_distinct_from_executor_and_persists() {
        let dir = tempfile::tempdir().unwrap();

        let exec = load_or_create_signing_key(dir.path(), &FILE).unwrap();
        let issuer = load_or_create_task_issuer_signing_key(dir.path(), &FILE).unwrap();
        assert_ne!(
            exec.verifying_key().as_bytes(),
            issuer.verifying_key().as_bytes(),
            "task-issuer key must not equal the executor key (role separation)"
        );

        // Distinct files on disk.
        assert!(dir.path().join(EXECUTOR_KEY_FILE).exists());
        assert!(dir.path().join(TASK_ISSUER_KEY_FILE).exists());

        // Stable across a "restart" (second load from the same dir).
        let issuer2 = load_or_create_task_issuer_signing_key(dir.path(), &FILE).unwrap();
        assert_eq!(
            issuer.verifying_key().as_bytes(),
            issuer2.verifying_key().as_bytes(),
            "task-issuer key must be stable across restarts"
        );
    }

    /// `from_env` provisions BOTH keys and they are role-separated.
    #[test]
    fn test_signing_key_distinct_per_state_dir() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let ka = load_or_create_signing_key(a.path(), &FILE).unwrap();
        let kb = load_or_create_signing_key(b.path(), &FILE).unwrap();
        assert_ne!(
            ka.verifying_key().as_bytes(),
            kb.verifying_key().as_bytes(),
            "separate state dirs must have independent identities"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_persisted_key_is_owner_read_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        load_or_create_signing_key(dir.path(), &FILE).unwrap();
        let mode = std::fs::metadata(dir.path().join(EXECUTOR_KEY_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o400, "private key must be mode 0400");
    }

    const NO_TPM: nucleus_federation::KeyCustody =
        nucleus_federation::KeyCustody::File(nucleus_federation::FileCustody::NoTpmConfigured);

    /// A file key on a node configured for TPM custody is refused, not
    /// signed with and not silently converted (ADR 0012).
    #[test]
    fn a_file_key_on_a_tpm_node_is_refused_without_the_waiver() {
        let dir = tempfile::tempdir().unwrap();
        load_or_create_jwt_svid_signing_key(dir.path(), &NO_TPM).unwrap();
        let tpm = nucleus_federation::KeyCustody::Tpm(nucleus_federation::TpmCustody::new(
            nucleus_federation::TpmEndpoint::Device(dir.path().join("no-such-tpm")),
        ));
        let err = load_or_create_jwt_svid_signing_key(dir.path(), &tpm).unwrap_err();
        assert!(
            err.contains(nucleus_federation::FILE_CUSTODY_WAIVER_FLAG),
            "{err}"
        );
        let waived = nucleus_federation::KeyCustody::File(nucleus_federation::FileCustody::Waived);
        load_or_create_jwt_svid_signing_key(dir.path(), &waived).unwrap();
    }

    /// The kid the node would sign its next assertion with.
    fn signing_kid(signer: nucleus_federation::keyring::KeyDirSigner) -> String {
        use nucleus_federation::CurrentSigner as _;
        std::sync::Arc::new(signer)
            .current()
            .expect("signs")
            .kid()
            .to_string()
    }

    /// The federation issuer key persists at 0400 and reloads as the SAME key —
    /// the same `kid` — across a restart, which is what an upstream that
    /// registered this node's JWKS depends on.
    #[test]
    fn the_federation_issuer_key_persists_read_only_with_a_stable_kid() {
        let dir = tempfile::tempdir().unwrap();
        let first = signing_kid(
            load_or_create_jwt_svid_signing_key(dir.path(), &NO_TPM).expect("generates"),
        );
        let path = dir.path().join(JWT_SVID_P256_KEY_FILE);
        assert!(path.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o400, "private key must be mode 0400");
        }
        let restarted =
            signing_kid(load_or_create_jwt_svid_signing_key(dir.path(), &NO_TPM).expect("reloads"));
        assert_eq!(first, restarted, "the kid changed across a restart");

        // And it is its own key, not one of the Ed25519 role keys' files.
        let other = tempfile::tempdir().unwrap();
        let elsewhere =
            signing_kid(load_or_create_jwt_svid_signing_key(other.path(), &NO_TPM).unwrap());
        assert_ne!(first, elsewhere, "two nodes share a federation key");
    }

    /// The node's signer — the object `federation_source` hands the broker —
    /// follows an operator's promote without a restart, and never signs with
    /// the staged key before it.
    #[test]
    fn the_running_node_signs_with_a_promoted_key_without_restart() {
        use nucleus_federation::CurrentSigner as _;
        use nucleus_federation::keyring::{KeyDir, RotationPolicy};
        let dir = tempfile::tempdir().unwrap();
        let node =
            std::sync::Arc::new(load_or_create_jwt_svid_signing_key(dir.path(), &NO_TPM).unwrap());
        let old = std::sync::Arc::clone(&node)
            .current()
            .unwrap()
            .kid()
            .to_string();

        let operator = KeyDir::new(dir.path());
        let t0 = 1_790_000_000;
        let staged = operator
            .stage(t0, &NO_TPM)
            .unwrap()
            .after
            .next
            .unwrap()
            .jwk
            .kid;
        assert_eq!(std::sync::Arc::clone(&node).current().unwrap().kid(), old);

        let policy = RotationPolicy::default();
        operator
            .promote(t0 + policy.promote_overlap().as_secs(), &policy)
            .unwrap();
        assert_eq!(
            std::sync::Arc::clone(&node).current().unwrap().kid(),
            staged
        );
    }

    /// A key someone else could read is refused, not silently replaced.
    #[cfg(unix)]
    #[test]
    fn a_federation_key_readable_by_others_stops_the_node() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        load_or_create_jwt_svid_signing_key(dir.path(), &NO_TPM).unwrap();
        let path = dir.path().join(JWT_SVID_P256_KEY_FILE);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();
        let err = load_or_create_jwt_svid_signing_key(dir.path(), &NO_TPM).unwrap_err();
        assert!(err.contains("mode"), "{err}");
    }

    #[test]
    fn test_corrupt_key_file_regenerates_without_panic() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(EXECUTOR_KEY_FILE), b"not valid pkcs8 der").unwrap();
        // Must not panic; must produce a usable, persisted key.
        let k = load_or_create_signing_key(dir.path(), &FILE).unwrap();
        let reloaded = load_or_create_signing_key(dir.path(), &FILE).unwrap();
        assert_eq!(
            k.verifying_key().as_bytes(),
            reloaded.verifying_key().as_bytes(),
            "after regeneration the new key must itself persist"
        );
    }

    // ── A2: the role keys sealed to the TPM ───────────────────────────────

    thread_local! {
        /// Runs between writing a sealed blob and reading it back to verify
        /// it: the seam a test uses to make the verification fail.
        pub(super) static BEFORE_VERIFY: std::cell::Cell<Option<fn(&Path)>> =
            const { std::cell::Cell::new(None) };
    }

    fn statement(dir: &Path) -> NodeKeyCustodyStatement {
        serde_json::from_slice(&std::fs::read(dir.join(NODE_KEY_CUSTODY_STATE_FILE)).unwrap())
            .unwrap()
    }

    fn entry(dir: &Path, role: NodeKeyRole) -> NodeKeyStatement {
        statement(dir)
            .keys
            .into_iter()
            .find(|k| k.role == role)
            .expect("the role is stated")
    }

    /// A sealed key in the directory is never read, regenerated over, or
    /// converted by file custody, waived or not.
    #[test]
    fn file_custody_refuses_a_sealed_key_and_leaves_it() {
        for why in [
            NodeKeyFileCustody::NoTpmConfigured,
            NodeKeyFileCustody::Waived,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let sealed = dir.path().join(NodeKeyRole::Executor.sealed_file());
            std::fs::write(&sealed, b"{}").unwrap();
            let err =
                load_or_create_signing_key(dir.path(), &NodeKeyCustody::File(why)).unwrap_err();
            assert!(err.contains("never crossed"), "{err}");
            assert!(
                !dir.path().join(EXECUTOR_KEY_FILE).exists(),
                "a file key was made"
            );
            assert_eq!(std::fs::read(&sealed).unwrap(), b"{}");
        }
    }

    /// A TPM node without the waiver does not run on its key file: a TPM that
    /// cannot be used stops start-up with an error naming the waiver, and the
    /// file is left exactly as it was for the next attempt.
    #[test]
    fn a_tpm_node_without_the_waiver_refuses_to_run_on_a_key_file() {
        let dir = tempfile::tempdir().unwrap();
        let key = load_or_create_signing_key(dir.path(), &FILE).unwrap();
        let before = std::fs::read(dir.path().join(EXECUTOR_KEY_FILE)).unwrap();
        let tpm = NodeKeyCustody::Sealed(TpmEndpoint::Device(dir.path().join("no-such-tpm")));
        let err = load_or_create_signing_key(dir.path(), &tpm).unwrap_err();
        assert!(err.contains(NODE_KEY_FILE_WAIVER_FLAG), "{err}");
        assert_eq!(
            std::fs::read(dir.path().join(EXECUTOR_KEY_FILE)).unwrap(),
            before
        );
        // With the waiver, the same directory runs on the same key, and the
        // statement says why it is a file.
        let waived = NodeKeyCustody::File(NodeKeyFileCustody::Waived);
        let again = load_or_create_signing_key(dir.path(), &waived).unwrap();
        assert_eq!(again.verifying_key(), key.verifying_key());
        assert_eq!(
            entry(dir.path(), NodeKeyRole::Executor).custody,
            CustodyRecord::File {
                reason: NodeKeyFileCustody::Waived.reason()
            }
        );
    }

    /// Every role key loaded is stated, in role order, with its public key.
    #[test]
    fn the_custody_statement_names_every_role_key() {
        let dir = tempfile::tempdir().unwrap();
        let e = load_or_create_signing_key(dir.path(), &FILE).unwrap();
        let c = load_or_create_cert_root_signing_key(dir.path(), &FILE).unwrap();
        load_or_create_approval_signing_key(dir.path(), &FILE).unwrap();
        load_or_create_task_issuer_signing_key(dir.path(), &FILE).unwrap();
        let doc = statement(dir.path());
        assert_eq!(doc.profile, NODE_KEY_CUSTODY_PROFILE);
        let roles: Vec<_> = doc.keys.iter().map(|k| k.role).collect();
        assert_eq!(
            roles,
            [
                NodeKeyRole::Executor,
                NodeKeyRole::TaskIssuer,
                NodeKeyRole::Approval,
                NodeKeyRole::CertRoot
            ]
        );
        assert_eq!(
            entry(dir.path(), NodeKeyRole::Executor).public_key,
            hex::encode(e.verifying_key().as_bytes())
        );
        assert_eq!(
            entry(dir.path(), NodeKeyRole::CertRoot).public_key,
            hex::encode(c.verifying_key().as_bytes())
        );
    }

    /// One swtpm process with its own state, killed on drop. Needs `swtpm` on
    /// `PATH` (or `NUCLEUS_SWTPM_BIN`); the tests that use it are ignored by
    /// default, and an ignored test is reported as ignored, never as a pass.
    struct Swtpm {
        child: std::process::Child,
        _state: tempfile::TempDir,
        addr: String,
    }

    impl Swtpm {
        fn start() -> Self {
            use std::process::{Command, Stdio};
            let port = {
                let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                l.local_addr().unwrap().port()
            };
            let dir = tempfile::tempdir().unwrap();
            let bin = std::env::var("NUCLEUS_SWTPM_BIN").unwrap_or_else(|_| "swtpm".into());
            let child = Command::new(bin)
                .args(["socket", "--tpm2", "--tpmstate"])
                .arg(format!("dir={}", dir.path().display()))
                .args(["--server"])
                .arg(format!("type=tcp,port={port},bindaddr=127.0.0.1"))
                .args(["--ctrl"])
                .arg(format!("type=tcp,port={},bindaddr=127.0.0.1", port + 1))
                .args(["--flags", "not-need-init,startup-clear"])
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("swtpm on PATH (or NUCLEUS_SWTPM_BIN)");
            let addr = format!("127.0.0.1:{port}");
            for _ in 0..100 {
                if std::net::TcpStream::connect(&addr).is_ok() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
            Self {
                child,
                _state: dir,
                addr,
            }
        }

        fn custody(&self) -> NodeKeyCustody {
            NodeKeyCustody::Sealed(TpmEndpoint::Socket(self.addr.clone()))
        }

        fn extend(&self, pcr: u8) {
            TpmEndpoint::Socket(self.addr.clone())
                .connect()
                .unwrap()
                .pcr_extend(pcr, &[pcr; 32])
                .unwrap();
        }
    }

    impl Drop for Swtpm {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// The disk holds the sealed blob and no key file; the blob does not
    /// contain the seed; the key unseals across a restart and signs.
    #[test]
    #[ignore = "needs swtpm on PATH"]
    fn a_sealed_key_unseals_and_signs() {
        use ed25519_dalek::Signer as _;
        let tpm = Swtpm::start();
        let dir = tempfile::tempdir().unwrap();
        let key = load_or_create_signing_key(dir.path(), &tpm.custody()).unwrap();
        assert!(!dir.path().join(EXECUTOR_KEY_FILE).exists());
        let sealed = dir.path().join(NodeKeyRole::Executor.sealed_file());
        let on_disk = std::fs::read(&sealed).unwrap();
        let (file, blob) = read_sealed(&sealed).unwrap();
        for bytes in [on_disk.as_slice(), blob.public(), blob.private()] {
            assert!(!contains(bytes, &key.to_bytes()), "the seed is on disk");
        }
        assert_eq!(file.origin, SealOrigin::Generated);
        let restarted = load_or_create_signing_key(dir.path(), &tpm.custody()).unwrap();
        assert_eq!(restarted.verifying_key(), key.verifying_key());
        let sig = restarted.sign(b"receipt");
        key.verifying_key().verify_strict(b"receipt", &sig).unwrap();
        match entry(dir.path(), NodeKeyRole::Executor).custody {
            CustodyRecord::TpmSealed {
                policy_pcrs,
                policy_digest,
                origin,
                ..
            } => {
                assert_eq!(policy_pcrs, boot_policy_pcrs());
                assert_eq!(policy_digest, hex::encode(blob.auth_policy()));
                assert_eq!(origin, SealOrigin::Generated);
            }
            other => panic!("stated as {other:?}"),
        }
    }

    /// A boot that differs in a policy PCR (8, the command line) cannot
    /// unseal: the old blob is set aside, kept, and a new key replaces it. A
    /// PCR outside the policy changes nothing.
    #[test]
    #[ignore = "needs swtpm on PATH"]
    fn extending_a_policy_pcr_stops_the_unseal() {
        let tpm = Swtpm::start();
        let dir = tempfile::tempdir().unwrap();
        let key = load_or_create_signing_key(dir.path(), &tpm.custody()).unwrap();
        tpm.extend(16);
        let same = load_or_create_signing_key(dir.path(), &tpm.custody()).unwrap();
        assert_eq!(same.verifying_key(), key.verifying_key());
        tpm.extend(8);
        let new = load_or_create_signing_key(dir.path(), &tpm.custody()).unwrap();
        assert_ne!(
            new.verifying_key(),
            key.verifying_key(),
            "the key unsealed in another boot state"
        );
        let kept: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".unusable-"))
            .collect();
        assert_eq!(kept.len(), 1, "the old blob was not kept aside");
        assert_eq!(
            entry(dir.path(), NodeKeyRole::Executor).public_key,
            hex::encode(new.verifying_key().as_bytes())
        );
    }

    /// A disk moved to another TPM holds no usable key: the blob does not
    /// unseal there, and nothing else on the disk is the key.
    #[test]
    #[ignore = "needs swtpm on PATH"]
    fn a_disk_moved_to_another_tpm_holds_no_usable_key() {
        let a = Swtpm::start();
        let b = Swtpm::start();
        let dir = tempfile::tempdir().unwrap();
        // A migrated key: the case where a key file once existed.
        let key = load_or_create_signing_key(dir.path(), &FILE).unwrap();
        load_or_create_signing_key(dir.path(), &a.custody()).unwrap();
        let elsewhere = load_or_create_signing_key(dir.path(), &b.custody()).unwrap();
        assert_ne!(
            elsewhere.verifying_key(),
            key.verifying_key(),
            "the moved disk produced the original key"
        );
    }

    /// Migration: an existing key file is sealed with the SAME public key, so
    /// everything it signed stays verifiable; the file is gone afterwards, and
    /// the statement records the migration.
    #[test]
    #[ignore = "needs swtpm on PATH"]
    fn migration_keeps_the_public_key_and_removes_the_file() {
        let tpm = Swtpm::start();
        let dir = tempfile::tempdir().unwrap();
        let mut before = Vec::new();
        for role in [
            NodeKeyRole::Executor,
            NodeKeyRole::TaskIssuer,
            NodeKeyRole::Approval,
            NodeKeyRole::CertRoot,
        ] {
            before.push(load_or_create_role_key(dir.path(), role, &FILE).unwrap());
        }
        for (role, old) in [
            NodeKeyRole::Executor,
            NodeKeyRole::TaskIssuer,
            NodeKeyRole::Approval,
            NodeKeyRole::CertRoot,
        ]
        .into_iter()
        .zip(&before)
        {
            let key = load_or_create_role_key(dir.path(), role, &tpm.custody()).unwrap();
            assert_eq!(key.verifying_key(), old.verifying_key(), "{role:?} changed");
            assert!(!dir.path().join(role.file()).exists(), "{role:?} file kept");
            let (file, _) = read_sealed(&dir.path().join(role.sealed_file())).unwrap();
            assert_eq!(file.origin, SealOrigin::MigratedFromFile);
            assert!(matches!(
                entry(dir.path(), role).custody,
                CustodyRecord::TpmSealed {
                    origin: SealOrigin::MigratedFromFile,
                    ..
                }
            ));
        }
        // And it reloads, sealed, as the same key.
        let again = load_or_create_signing_key(dir.path(), &tpm.custody()).unwrap();
        assert_eq!(again.verifying_key(), before[0].verifying_key());
    }

    /// The key file is removed only after the sealed blob ON DISK unsealed to
    /// the key: when that check fails, the file stays, the bad blob is removed,
    /// and the node does not start.
    #[test]
    #[ignore = "needs swtpm on PATH"]
    fn the_key_file_outlives_a_sealed_blob_that_does_not_verify() {
        fn corrupt(path: &Path) {
            let (mut file, _) = read_sealed(path).unwrap();
            let mut private = STANDARD.decode(&file.private).unwrap();
            let last = private.len() - 1;
            private[last] ^= 0x01;
            file.private = STANDARD.encode(private);
            std::fs::remove_file(path).unwrap();
            std::fs::write(path, serde_json::to_vec(&file).unwrap()).unwrap();
        }
        let tpm = Swtpm::start();
        let dir = tempfile::tempdir().unwrap();
        let key = load_or_create_signing_key(dir.path(), &FILE).unwrap();
        let plain = std::fs::read(dir.path().join(EXECUTOR_KEY_FILE)).unwrap();
        BEFORE_VERIFY.with(|h| h.set(Some(corrupt)));
        let err = load_or_create_signing_key(dir.path(), &tpm.custody()).unwrap_err();
        BEFORE_VERIFY.with(|h| h.set(None));
        assert!(err.contains("round-trip"), "{err}");
        assert_eq!(
            std::fs::read(dir.path().join(EXECUTOR_KEY_FILE)).unwrap(),
            plain,
            "the key file did not survive a failed verification"
        );
        assert!(
            !dir.path()
                .join(NodeKeyRole::Executor.sealed_file())
                .exists()
        );
        // The next start migrates it.
        let migrated = load_or_create_signing_key(dir.path(), &tpm.custody()).unwrap();
        assert_eq!(migrated.verifying_key(), key.verifying_key());
    }

    /// A crash at either point of a migration leaves a usable key, and the
    /// next start completes it with the same public key:
    /// * before the rename — the file and a stray temporary;
    /// * after the rename, before the file was deleted — both.
    ///
    /// A file that holds a DIFFERENT key beside a sealed one is refused.
    #[test]
    #[ignore = "needs swtpm on PATH"]
    fn a_crash_mid_migration_leaves_a_usable_key() {
        let tpm = Swtpm::start();
        let NodeKeyCustody::Sealed(endpoint) = tpm.custody() else {
            panic!("an swtpm custody is sealed custody")
        };

        // Before the rename.
        let dir = tempfile::tempdir().unwrap();
        let key = load_or_create_signing_key(dir.path(), &FILE).unwrap();
        let sealed = dir.path().join(NodeKeyRole::Executor.sealed_file());
        let mut tmp = sealed.as_os_str().to_owned();
        tmp.push(".tmp");
        std::fs::write(&tmp, b"{\"torn").unwrap();
        let after = load_or_create_signing_key(dir.path(), &tpm.custody()).unwrap();
        assert_eq!(after.verifying_key(), key.verifying_key());
        assert!(!dir.path().join(EXECUTOR_KEY_FILE).exists());
        assert!(!PathBuf::from(&tmp).exists());

        // After the rename, before the delete.
        let dir = tempfile::tempdir().unwrap();
        let key = load_or_create_signing_key(dir.path(), &FILE).unwrap();
        let sealed = dir.path().join(NodeKeyRole::Executor.sealed_file());
        seal_and_verify(
            &endpoint,
            &sealed,
            NodeKeyRole::Executor,
            &key,
            SealOrigin::MigratedFromFile,
        )
        .unwrap();
        assert!(dir.path().join(EXECUTOR_KEY_FILE).exists());
        let after = load_or_create_signing_key(dir.path(), &tpm.custody()).unwrap();
        assert_eq!(after.verifying_key(), key.verifying_key());
        assert!(
            !dir.path().join(EXECUTOR_KEY_FILE).exists(),
            "the interrupted migration left the key file"
        );

        // A different key in the file: refused, both kept.
        let dir = tempfile::tempdir().unwrap();
        load_or_create_signing_key(dir.path(), &FILE).unwrap();
        let other = generate_signing_key();
        seal_and_verify(
            &endpoint,
            &dir.path().join(NodeKeyRole::Executor.sealed_file()),
            NodeKeyRole::Executor,
            &other,
            SealOrigin::Generated,
        )
        .unwrap();
        let err = load_or_create_signing_key(dir.path(), &tpm.custody()).unwrap_err();
        assert!(err.contains("DIFFERENT"), "{err}");
        assert!(dir.path().join(EXECUTOR_KEY_FILE).exists());
    }
}
