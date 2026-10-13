//! The attestation requirement (`--require-attestation`) for tool proxy requests.
//!
//! A network caller meets the requirement only with a launch the proxy checked
//! itself: the client certificate its mTLS handshake presented, verified against
//! the listener's trust bundle by [`nucleus_identity::VerifiedLaunch::verify`],
//! the one decider for "this leaf carries a launch a trusted CA vouched for"
//! (ADR 0007 G-1, ADR 0016 D1).
//!
//! # Flow
//!
//! 1. The caller completes an mTLS handshake with an SVID.
//! 2. [`VerifiedLaunch::verify`] chains the leaf to the trust bundle the mTLS
//!    listener was built from, then reads its launch extension
//!    (OID 1.3.6.1.4.1.57212.1.1). Both are required, in that order.
//! 3. The verified measurement is compared against the configured allow-lists.
//! 4. The assurance floor (North Star C9) is checked over the same certificate.
//!
//! # What is not evidence
//!
//! A launch a caller asserts about itself is not evidence (ADR 0007 C-1, C-2).
//! There used to be an `x-nucleus-attestation` request header carrying an
//! unsigned base64 `LaunchAttestation`; any caller could satisfy the requirement
//! by sending one. It is gone, and nothing reads it: a request without a
//! chain-checked certificate on a listener with no trust bundle is refused, by
//! name ([`LaunchRoots::Absent`]).
//!
//! # Configuration
//!
//! - `--require-attestation`: enable the requirement (needs `--mtls` to be
//!   satisfiable by a network caller)
//! - `--allowed-kernel-hashes`, `--allowed-rootfs-hashes`,
//!   `--allowed-config-hashes`: comma-separated SHA-256 allow-lists
//!
//! If no allowed hashes are specified but attestation is required, any launch a
//! trusted CA vouched for is accepted.

use ed25519_dalek::VerifyingKey;
use nucleus_identity::{
    AssuranceLevel, LaunchAttestation, TrustBundle, VerifiedAttestation, VerifiedLaunch,
};
use portcullis::mediation_receipt::MediationReceipt;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Configuration for attestation verification.
#[derive(Clone, Debug, Default)]
pub struct AttestationConfig {
    /// Whether attestation is required for all requests.
    pub require_attestation: bool,
    /// Set of allowed kernel hashes (SHA-256, hex-encoded).
    /// Empty means any kernel hash is allowed.
    pub allowed_kernel_hashes: HashSet<String>,
    /// Set of allowed rootfs hashes (SHA-256, hex-encoded).
    /// Empty means any rootfs hash is allowed.
    pub allowed_rootfs_hashes: HashSet<String>,
    /// Set of allowed config hashes (SHA-256, hex-encoded).
    /// Empty means any config hash is allowed.
    pub allowed_config_hashes: HashSet<String>,
    /// Minimum normalized assurance level a request's SVID must carry (North Star
    /// C9). `L0Bearer` (the default) imposes no floor. A floor above `L0Bearer`
    /// makes attestation effectively required and refuses any SVID whose verified
    /// assurance is below it — fail-closed on absent/invalid evidence. Note a
    /// `L2Device`+ floor refuses every SVID until the EK-manufacturer root lands
    /// (residency alone is `L1Software`).
    pub min_assurance: AssuranceLevel,
}

impl AttestationConfig {
    /// Creates a new attestation config with attestation required.
    pub fn required() -> Self {
        Self {
            require_attestation: true,
            ..Default::default()
        }
    }

    /// Adds allowed kernel hashes from a comma-separated string.
    pub fn with_kernel_hashes(mut self, hashes: &str) -> Self {
        for hash in hashes.split(',') {
            let hash = hash.trim().to_lowercase();
            if !hash.is_empty() {
                self.allowed_kernel_hashes.insert(hash);
            }
        }
        self
    }

    /// Adds allowed rootfs hashes from a comma-separated string.
    pub fn with_rootfs_hashes(mut self, hashes: &str) -> Self {
        for hash in hashes.split(',') {
            let hash = hash.trim().to_lowercase();
            if !hash.is_empty() {
                self.allowed_rootfs_hashes.insert(hash);
            }
        }
        self
    }

    /// Adds allowed config hashes from a comma-separated string.
    pub fn with_config_hashes(mut self, hashes: &str) -> Self {
        for hash in hashes.split(',') {
            let hash = hash.trim().to_lowercase();
            if !hash.is_empty() {
                self.allowed_config_hashes.insert(hash);
            }
        }
        self
    }

    /// Sets the minimum assurance floor. A floor above `L0Bearer` also makes
    /// attestation required (a floor cannot be checked without a client cert).
    pub fn with_min_assurance(mut self, level: AssuranceLevel) -> Self {
        self.min_assurance = level;
        if level > AssuranceLevel::L0Bearer {
            self.require_attestation = true;
        }
        self
    }
}

/// Where a peer's launch can be chain-checked on this proxy's network listener.
///
/// Two constructors and no `Default` (ADR 0007 B-1): "no source" is a value the
/// requirement refuses by name, never an `Option::None` read as "unrestricted"
/// (B-2).
#[derive(Clone, Debug)]
pub enum LaunchRoots {
    /// The trust bundle the mTLS listener verifies client certificates
    /// against. A client certificate's launch is checked against exactly this.
    MtlsBundle(Arc<TrustBundle>),
    /// The proxy serves no mTLS listener, so no network caller can present a
    /// chain-checked launch. The requirement refuses every such request.
    Absent,
}

impl LaunchRoots {
    /// The roots of the mTLS listener the proxy will serve, if it serves one.
    /// Read from the same `MtlsConfig` the listener is built from, so the
    /// handshake and the launch check cannot disagree about the CA (G-1).
    pub fn of(mtls: Option<&nucleus_identity::mtls::MtlsConfig>) -> Self {
        match mtls {
            Some(config) => Self::MtlsBundle(Arc::new(config.trust_bundle.clone())),
            None => Self::Absent,
        }
    }
}

/// Extracted attestation information.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AttestationInfo {
    /// Kernel hash as hex string.
    pub kernel_hash: String,
    /// Rootfs hash as hex string.
    pub rootfs_hash: String,
    /// Config hash as hex string.
    pub config_hash: String,
    /// Timestamp when attestation was computed.
    pub timestamp: String,
}

impl From<&LaunchAttestation> for AttestationInfo {
    fn from(att: &LaunchAttestation) -> Self {
        Self {
            kernel_hash: hex::encode(att.kernel_hash()),
            rootfs_hash: hex::encode(att.rootfs_hash()),
            config_hash: hex::encode(att.config_hash()),
            timestamp: att.timestamp().to_rfc3339(),
        }
    }
}

/// Attestation verifier for tool proxy.
#[derive(Clone)]
pub struct AttestationVerifier {
    config: Arc<AttestationConfig>,
    roots: LaunchRoots,
}

impl AttestationVerifier {
    /// Creates a new attestation verifier with the given config, deciding a
    /// client certificate's launch against `roots`.
    pub fn new(config: AttestationConfig, roots: LaunchRoots) -> Self {
        if config.require_attestation {
            let count = |set: &HashSet<String>| {
                if set.is_empty() {
                    "any".to_string()
                } else {
                    set.len().to_string()
                }
            };
            info!(
                "attestation verification enabled: kernel_hashes={}, rootfs_hashes={}, config_hashes={}",
                count(&config.allowed_kernel_hashes),
                count(&config.allowed_rootfs_hashes),
                count(&config.allowed_config_hashes),
            );
            if let LaunchRoots::Absent = roots {
                warn!(
                    "attestation required without --mtls: no network caller can present a \
                     chain-checked launch, so every request outside the workload door is refused"
                );
            }
        }
        Self {
            config: Arc::new(config),
            roots,
        }
    }

    /// The launch a client certificate carries, chain-checked against the
    /// listener's trust bundle, then compared against the allow-lists.
    ///
    /// # Errors
    /// No chain-checked source on this listener, a leaf the bundle did not
    /// issue, a leaf with no measured launch, or a measurement off the lists.
    fn verify_peer_launch(&self, cert_der: &[u8]) -> Result<VerifiedLaunch, String> {
        let bundle = match &self.roots {
            LaunchRoots::MtlsBundle(bundle) => bundle,
            LaunchRoots::Absent => {
                return Err(
                    "attestation required but this proxy has no mTLS trust bundle to check a \
                     peer's launch against"
                        .to_string(),
                );
            }
        };
        let verified = VerifiedLaunch::verify(cert_der, bundle)
            .map_err(|e| format!("peer launch not verified: {e}"))?;
        let info = AttestationInfo::from(verified.launch());
        debug!(
            "attestation present: kernel={}, rootfs={}, config={}",
            &info.kernel_hash[..16],
            &info.rootfs_hash[..16],
            &info.config_hash[..16]
        );
        self.validate_attestation(&info)?;
        Ok(verified)
    }

    /// Validates attestation info against configured requirements.
    fn validate_attestation(&self, info: &AttestationInfo) -> Result<(), String> {
        for (what, allowed, got) in [
            (
                "kernel",
                &self.config.allowed_kernel_hashes,
                &info.kernel_hash,
            ),
            (
                "rootfs",
                &self.config.allowed_rootfs_hashes,
                &info.rootfs_hash,
            ),
            (
                "config",
                &self.config.allowed_config_hashes,
                &info.config_hash,
            ),
        ] {
            if !allowed.is_empty() && !allowed.contains(got) {
                return Err(format!(
                    "{what} hash {} not in allowed list",
                    got.get(..16).unwrap_or(got)
                ));
            }
        }
        Ok(())
    }

    /// Returns whether attestation is required.
    pub fn is_required(&self) -> bool {
        self.config.require_attestation
    }

    /// Enforces the assurance floor (North Star C9) over the certificate whose
    /// launch `launch` verified. The floor is never reached without one, so the
    /// launch half of the assurance is the witness, not a flag.
    ///
    /// The launch attestation establishes at most `L1Software`; TPM residency
    /// evidence carried by the client certificate can raise the effective level,
    /// and a present-but-invalid or replayed proof makes this err (fail-closed).
    /// Returns `Err(reason)`, naming the verified workload, when the SVID's
    /// assurance is below the floor. A no-op (`Ok`) when the floor is `L0Bearer`.
    fn enforce_floor(&self, cert_der: &[u8], launch: &VerifiedLaunch) -> Result<(), String> {
        let min = self.config.min_assurance;
        if min <= AssuranceLevel::L0Bearer {
            return Ok(());
        }
        let who = launch.spiffe_id();
        let level = nucleus_identity::tpm_devid::effective_assurance(cert_der, true)
            .map_err(|e| format!("residency evidence of {who} invalid: {e}"))?;
        if level < min {
            return Err(format!(
                "assurance {level:?} of {who} below required floor {min:?}"
            ));
        }
        Ok(())
    }

    /// The attestation requirement, decided over what the transport proved.
    ///
    /// The requirement authenticates a *network* caller (the host, the node)
    /// by the launch its chain-checked certificate carries. Each kind of
    /// evidence is its own arm, matched exhaustively (ADR 0007 E-2), so a new
    /// transport cannot fall through to a pass (B-3):
    ///
    /// - [`TransportEvidence::ClientCert`]: a [`VerifiedLaunch`] over the
    ///   certificate against [`LaunchRoots`], then the assurance floor over it.
    /// - [`TransportEvidence::DoorPeer`]: satisfied. The workload door already
    ///   authenticated the caller by its kernel-reported uid, and the evidence
    ///   exists only on one of the door's own routes
    ///   ([`crate::workload_door::DoorAdmission`]). A local peer proven to be
    ///   the workload has no certificate to attest and does not need one.
    /// - [`TransportEvidence::None`]: refused. Absence is not a pass (A-5), and
    ///   nothing a request says about itself stands in for a certificate.
    ///
    /// # Errors
    /// The reason the requirement is not met.
    pub(crate) fn admit(&self, evidence: &TransportEvidence<'_>) -> Result<(), String> {
        if !self.is_required() {
            return Ok(());
        }
        match evidence {
            TransportEvidence::DoorPeer(admission) => {
                debug!(
                    uid = admission.uid(),
                    route = ?admission.route(),
                    "attestation requirement met by the workload door's peer credentials"
                );
                Ok(())
            }
            TransportEvidence::ClientCert(der) => {
                info!(
                    event = "attestation_verify_mtls",
                    "verifying attestation from client certificate"
                );
                let launch = self.verify_peer_launch(der)?;
                // North Star C9: the assurance floor, fail-closed on absent,
                // invalid or replayed residency evidence. A no-op at L0Bearer.
                self.enforce_floor(der, &launch)?;
                debug!(
                    spiffe_id = launch.spiffe_id(),
                    "attestation verified against the mTLS trust bundle"
                );
                Ok(())
            }
            TransportEvidence::None => Err(
                "attestation required but not provided: only a chain-checked mTLS client \
                 certificate carries a launch"
                    .to_string(),
            ),
        }
    }
}

/// What the transport proved about a request's caller, before any header is
/// read. [`AttestationVerifier::admit`] decides the requirement over it, and
/// [`TransportEvidence::ingress`] decides which auth tiers are open to it, so
/// "which listener" is read once (ADR 0007 G-1).
#[derive(Debug)]
pub(crate) enum TransportEvidence<'a> {
    /// A client certificate the mTLS handshake presented (DER).
    ClientCert(&'a [u8]),
    /// A peer the workload door admitted by `SO_PEERCRED`, on one of the
    /// door's own routes. Only the door's accept path and route layer can
    /// produce the value inside (ADR 0007 C-1, C-2).
    DoorPeer(&'a crate::workload_door::DoorAdmission),
    /// Neither: a caller on the main listener with no client certificate.
    None,
}

impl<'a> TransportEvidence<'a> {
    /// Read the evidence from a request's extensions.
    ///
    /// A connection the door accepted must carry a door route's admission. One
    /// without it (a door connection outside the door's route table) is
    /// refused rather than read as a main-listener caller, and an admission
    /// without a door connection is refused too: neither can be built, and
    /// "cannot happen" is not a reason to pass (ADR 0007 A-2).
    ///
    /// # Errors
    /// The two impossible shapes, named.
    pub(crate) fn of(extensions: &'a axum::http::Extensions) -> Result<Self, String> {
        use crate::workload_door::{DoorAdmission, DoorPeer};
        use axum::extract::ConnectInfo;
        use nucleus_identity::mtls::{ClientCertInfo, MtlsConnectInfo};

        match (
            extensions.get::<ConnectInfo<DoorPeer>>(),
            extensions.get::<DoorAdmission>(),
        ) {
            (Some(ConnectInfo(peer)), Some(admission)) if admission.uid() == peer.uid() => {
                Ok(Self::DoorPeer(admission))
            }
            (Some(_), Some(_)) => {
                Err("the door admission names a different peer than the connection".to_string())
            }
            (Some(_), None) => Err(
                "a workload door connection reached a route outside the door's table".to_string(),
            ),
            (None, Some(_)) => {
                Err("a door admission arrived on a connection the door did not accept".to_string())
            }
            (None, None) => Ok(extensions
                .get::<MtlsConnectInfo>()
                .and_then(|info| info.client_cert.as_ref())
                .or_else(|| extensions.get::<ClientCertInfo>())
                .map_or(Self::None, |cert| Self::ClientCert(cert.der()))),
        }
    }

    /// Which listener the evidence came through.
    pub(crate) fn ingress(&self) -> crate::auth::Ingress {
        match self {
            Self::DoorPeer(admission) => crate::auth::Ingress::WorkloadDoor {
                uid: admission.uid(),
            },
            Self::ClientCert(_) | Self::None => crate::auth::Ingress::Listener,
        }
    }
}

/// Relying-party cross-check for a forensic [`MediationReceipt`] (North Star C9 /
/// signed-agent-actions): verify the mediator's signature, that the receipt's
/// self-claimed `{signer_assurance, signer_backend}` **exactly match** an
/// independently-verified attestation of the signer's SVID, **and** — when the
/// attestation names a signing key ([`VerifiedAttestation::subject_key_sha256`]) —
/// that the receipt was signed by THAT key (the deep key-binding, closing the
/// key-substitution hole).
///
/// This is what makes the receipt's self-claim non-load-bearing: a receipt is a
/// perfectly valid signature over whatever assurance the signer *wrote*, so the
/// claim is believed only when it equals the attestation a relying party derived
/// itself (e.g. via [`effective_assurance`](nucleus_identity::tpm_devid::effective_assurance)
/// over the signer's SVID). An inflated claim — an `L1Software` signer asserting
/// `L2Device` / `apple-sep` — is rejected here, never trusted on the signer's word.
///
/// Returns the cross-checked assurance level. Fail-closed on any mismatch.
///
/// Not yet wired to a live path: emitting receipts on the mediation path (the
/// tool-proxy issuing them with its own assurance) and invoking this from a
/// relying party are follow bricks; this is the verified cross-check primitive.
#[allow(dead_code)]
pub fn verify_attested_receipt(
    receipt: &MediationReceipt,
    signer_pubkey: &VerifyingKey,
    attestation: &VerifiedAttestation,
) -> Result<AssuranceLevel, String> {
    // 1. The signature must hold. Because `{signer_assurance, signer_backend}` are
    //    in the signed preimage, a post-issue tamper of either breaks this.
    receipt
        .verify(signer_pubkey)
        .map_err(|e| format!("receipt signature invalid: {e}"))?;

    // 2. The self-claim must EQUAL the independently-verified attestation — the
    //    load-bearing check. Backend first, then the assurance level.
    if receipt.signer_backend != attestation.backend() {
        return Err(format!(
            "signer backend claim {:?} does not match verified attestation backend {:?}",
            receipt.signer_backend,
            attestation.backend()
        ));
    }
    if receipt.signer_assurance != attestation.assurance().as_u8() {
        return Err(format!(
            "signer assurance claim L{} does not match verified attestation L{} \
             (inflated claim rejected)",
            receipt.signer_assurance,
            attestation.assurance().as_u8()
        ));
    }

    // 3. The DEEP key-binding, when the attestation names a signing key: the
    //    receipt must be signed by THAT key, not merely by some key handed in
    //    alongside the attestation. Without this, a receipt signed by any key
    //    could borrow a hardware-rooted SVID's backend+assurance by presenting
    //    that SVID's attestation next to an unrelated `signer_pubkey`. When the
    //    attestation does NOT name a key (`None` — a self-measured launch, or a
    //    TPM Name that is not a bare Ed25519 key), the binding cannot be checked
    //    here; the caller's contract is then to have obtained `signer_pubkey`
    //    from the attested SVID itself.
    if let Some(expected) = attestation.subject_key_sha256() {
        let mut hasher = Sha256::new();
        hasher.update(signer_pubkey.to_bytes());
        let got: [u8; 32] = hasher.finalize().into();
        if got != expected {
            return Err(
                "receipt signing key is not the attested subject key -- key substitution rejected"
                    .to_string(),
            );
        }
    }

    Ok(attestation.assurance())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nucleus_identity::{CaClient, CsrOptions, Identity, SelfSignedCa};

    const TRUST_DOMAIN: &str = "nucleus.local";

    fn launch() -> LaunchAttestation {
        LaunchAttestation::from_hashes([0x11; 32], [0x22; 32], [0x33; 32])
    }

    /// A leaf the way the node issues one: signed by `ca`, launch embedded.
    async fn attested_leaf(ca: &SelfSignedCa) -> Vec<u8> {
        let identity = Identity::new(TRUST_DOMAIN, "pods", "p1");
        let csr = CsrOptions::new(identity.to_spiffe_uri())
            .generate()
            .unwrap();
        ca.sign_attested_csr(
            csr.csr(),
            csr.private_key(),
            &identity,
            std::time::Duration::from_secs(3600),
            &launch(),
        )
        .await
        .unwrap()
        .leaf()
        .der()
        .to_vec()
    }

    /// A leaf `ca` issued with no launch claim.
    async fn plain_leaf(ca: &SelfSignedCa) -> Vec<u8> {
        let identity = Identity::new(TRUST_DOMAIN, "pods", "p1");
        let csr = CsrOptions::new(identity.to_spiffe_uri())
            .generate()
            .unwrap();
        ca.sign_csr(
            csr.csr(),
            csr.private_key(),
            &identity,
            std::time::Duration::from_secs(3600),
        )
        .await
        .unwrap()
        .leaf()
        .der()
        .to_vec()
    }

    /// The forgery: a self-signed leaf carrying the launch OID and a
    /// well-formed measurement. Anyone can make one in a few lines.
    fn forged_leaf() -> Vec<u8> {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.subject_alt_names = vec![rcgen::SanType::URI(
            rcgen::string::Ia5String::try_from(format!("spiffe://{TRUST_DOMAIN}/ns/pods/sa/p1"))
                .unwrap(),
        )];
        params
            .custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                nucleus_identity::oid::OID_NUCLEUS_ATTESTATION_TUPLE,
                launch().to_der(),
            ));
        let key = rcgen::KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().der().to_vec()
    }

    fn roots(ca: &SelfSignedCa) -> LaunchRoots {
        LaunchRoots::MtlsBundle(Arc::new(ca.trust_bundle().clone()))
    }

    fn required(ca: &SelfSignedCa) -> AttestationVerifier {
        AttestationVerifier::new(AttestationConfig::required(), roots(ca))
    }

    #[test]
    fn test_attestation_config_default() {
        let config = AttestationConfig::default();
        assert!(!config.require_attestation);
        assert!(config.allowed_kernel_hashes.is_empty());
        assert!(config.allowed_rootfs_hashes.is_empty());
        // No floor by default — existing deployments are unaffected.
        assert_eq!(config.min_assurance, AssuranceLevel::L0Bearer);
    }

    #[test]
    fn test_min_assurance_floor_implies_required() {
        // A floor above L0 makes attestation required (can't check a floor without
        // a client cert); an L0 floor leaves require_attestation untouched.
        let floored = AttestationConfig::default().with_min_assurance(AssuranceLevel::L2Device);
        assert_eq!(floored.min_assurance, AssuranceLevel::L2Device);
        assert!(floored.require_attestation);

        let no_floor = AttestationConfig::default().with_min_assurance(AssuranceLevel::L0Bearer);
        assert_eq!(no_floor.min_assurance, AssuranceLevel::L0Bearer);
        assert!(!no_floor.require_attestation);
    }

    #[test]
    fn test_attestation_config_with_hashes() {
        let config = AttestationConfig::required()
            .with_kernel_hashes("abc123,def456")
            .with_rootfs_hashes("111222");

        assert!(config.require_attestation);
        assert_eq!(config.allowed_kernel_hashes.len(), 2);
        assert!(config.allowed_kernel_hashes.contains("abc123"));
        assert!(config.allowed_kernel_hashes.contains("def456"));
        assert_eq!(config.allowed_rootfs_hashes.len(), 1);
        assert!(config.allowed_rootfs_hashes.contains("111222"));
    }

    #[test]
    fn test_attestation_info_from_launch_attestation() {
        let attestation = LaunchAttestation::from_hashes([0xaa; 32], [0xbb; 32], [0xcc; 32]);

        let info = AttestationInfo::from(&attestation);
        assert_eq!(info.kernel_hash, "aa".repeat(32));
        assert_eq!(info.rootfs_hash, "bb".repeat(32));
        assert_eq!(info.config_hash, "cc".repeat(32));
    }

    fn info(kernel: &str) -> AttestationInfo {
        AttestationInfo {
            kernel_hash: kernel.repeat(32),
            rootfs_hash: "bb".repeat(32),
            config_hash: "cc".repeat(32),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn test_validate_attestation_any_allowed() {
        let verifier = AttestationVerifier::new(AttestationConfig::required(), LaunchRoots::Absent);
        assert_eq!(verifier.validate_attestation(&info("aa")), Ok(()));
    }

    #[test]
    fn test_validate_attestation_kernel_hash_mismatch() {
        let verifier = AttestationVerifier::new(
            AttestationConfig::required().with_kernel_hashes(&"dd".repeat(32)),
            LaunchRoots::Absent,
        );
        let refused = verifier
            .validate_attestation(&info("aa"))
            .expect_err("a kernel off the list is refused");
        assert!(refused.contains("kernel hash"), "{refused}");
    }

    #[test]
    fn test_validate_attestation_kernel_hash_match() {
        let verifier = AttestationVerifier::new(
            AttestationConfig::required().with_kernel_hashes(&"aa".repeat(32)),
            LaunchRoots::Absent,
        );
        assert_eq!(verifier.validate_attestation(&info("aa")), Ok(()));
    }

    /// Not required: a certificate that does not even parse is not looked at.
    #[test]
    fn test_verifier_no_attestation_not_required() {
        let ca = SelfSignedCa::new(TRUST_DOMAIN).unwrap();
        let open = AttestationVerifier::new(AttestationConfig::default(), roots(&ca));
        assert_eq!(open.admit(&TransportEvidence::ClientCert(&[])), Ok(()));
    }

    /// Required: a certificate that does not parse fails closed.
    #[test]
    fn test_verifier_no_attestation_required() {
        let ca = SelfSignedCa::new(TRUST_DOMAIN).unwrap();
        assert!(
            required(&ca)
                .admit(&TransportEvidence::ClientCert(&[]))
                .is_err()
        );
    }

    /// The retired header path, at the unit level: a well-formed launch that
    /// survives a base64 round trip — exactly what the `x-nucleus-attestation`
    /// header used to carry — is not evidence. A request with no certificate
    /// is refused whatever its headers say, because `admit` no longer reads
    /// them (its signature has no `HeaderMap`).
    #[test]
    fn test_base64_roundtrip() {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let der = launch().to_der();
        let decoded = STANDARD.decode(STANDARD.encode(&der)).unwrap();
        assert!(LaunchAttestation::from_der(&decoded).is_ok());
        let ca = SelfSignedCa::new(TRUST_DOMAIN).unwrap();
        assert!(required(&ca).admit(&TransportEvidence::None).is_err());
    }

    /// A header carrying a valid attestation used to meet the requirement
    /// (red on 7d7c3c70d). With the header path deleted, the same valid
    /// launch meets it only inside a certificate the trusted CA signed; the
    /// end-to-end header refusal is
    /// `workload_door::tests::a_forged_attestation_header_does_not_meet_the_requirement`.
    #[tokio::test]
    async fn test_verify_header_valid_attestation() {
        let ca = SelfSignedCa::new(TRUST_DOMAIN).unwrap();
        let verifier = required(&ca);
        assert!(verifier.admit(&TransportEvidence::None).is_err());
        let leaf = attested_leaf(&ca).await;
        assert_eq!(
            verifier.admit(&TransportEvidence::ClientCert(&leaf)),
            Ok(())
        );
    }

    /// The floor directly, over a verified launch: L0 imposes nothing, an L1
    /// floor admits a CA-issued launch (base `L1Software`), and an L2 floor
    /// refuses it, naming the workload — never over-admits L2.
    #[tokio::test]
    async fn enforce_floor_admits_refuses_and_fails_closed() {
        let ca = SelfSignedCa::new(TRUST_DOMAIN).unwrap();
        let leaf = attested_leaf(&ca).await;
        let launch = VerifiedLaunch::verify(&leaf, ca.trust_bundle()).unwrap();
        let floor = |level| {
            AttestationVerifier::new(
                AttestationConfig::default().with_min_assurance(level),
                roots(&ca),
            )
        };
        assert!(
            floor(AssuranceLevel::L0Bearer)
                .enforce_floor(&leaf, &launch)
                .is_ok()
        );
        assert!(
            floor(AssuranceLevel::L1Software)
                .enforce_floor(&leaf, &launch)
                .is_ok()
        );
        let refused = floor(AssuranceLevel::L2Device)
            .enforce_floor(&leaf, &launch)
            .expect_err("L2 refuses a software launch");
        assert!(refused.contains(launch.spiffe_id()), "{refused}");
    }

    /// The control for every refusal below: a launch the trusted CA issued,
    /// presented as the mTLS client certificate, meets the requirement — with
    /// no allow-list, and with allow-lists that name its measurement.
    #[tokio::test]
    async fn a_chain_checked_launch_meets_the_requirement() {
        let ca = SelfSignedCa::new(TRUST_DOMAIN).unwrap();
        let leaf = attested_leaf(&ca).await;
        assert_eq!(
            required(&ca).admit(&TransportEvidence::ClientCert(&leaf)),
            Ok(())
        );
        let listed = AttestationVerifier::new(
            AttestationConfig::required()
                .with_kernel_hashes(&"11".repeat(32))
                .with_rootfs_hashes(&"22".repeat(32))
                .with_config_hashes(&"33".repeat(32)),
            roots(&ca),
        );
        assert_eq!(listed.admit(&TransportEvidence::ClientCert(&leaf)), Ok(()));
    }

    /// **The chain check is load-bearing.** A self-signed leaf carrying the
    /// launch OID and a well-formed measurement is refused as the client
    /// certificate. Red on main: `admit` read the extension off the leaf with
    /// no issuer check, so this forgery met the requirement. Replacing
    /// `VerifiedLaunch::verify` with a bare extension read turns it green.
    #[tokio::test]
    async fn a_self_signed_leaf_carrying_the_launch_oid_is_refused() {
        let ca = SelfSignedCa::new(TRUST_DOMAIN).unwrap();
        let forged = forged_leaf();
        assert!(
            nucleus_identity::attestation::extract_launch_attestation(&forged).is_some(),
            "the forgery must carry a parseable launch, or this test proves nothing"
        );
        let refused = required(&ca)
            .admit(&TransportEvidence::ClientCert(&forged))
            .expect_err("a self-signed launch is not evidence");
        assert!(refused.contains("not issued by a trusted CA"), "{refused}");
    }

    /// A launch another CA issued is a forgery for this proxy too.
    #[tokio::test]
    async fn a_launch_a_foreign_ca_issued_is_refused() {
        let ours = SelfSignedCa::new(TRUST_DOMAIN).unwrap();
        let theirs = SelfSignedCa::new(TRUST_DOMAIN).unwrap();
        let leaf = attested_leaf(&theirs).await;
        let refused = required(&ours)
            .admit(&TransportEvidence::ClientCert(&leaf))
            .expect_err("a foreign CA's launch is refused");
        assert!(refused.contains("not issued by a trusted CA"), "{refused}");
    }

    /// A leaf the trusted CA issued without a launch is refused: absence is
    /// not a pass (A-5).
    #[tokio::test]
    async fn a_trusted_leaf_without_a_launch_is_refused() {
        let ca = SelfSignedCa::new(TRUST_DOMAIN).unwrap();
        let leaf = plain_leaf(&ca).await;
        let refused = required(&ca)
            .admit(&TransportEvidence::ClientCert(&leaf))
            .expect_err("no launch on a required proxy is refused");
        assert!(refused.contains("launch"), "{refused}");
    }

    /// A verified launch outside an allow-list is refused, by which hash.
    #[tokio::test]
    async fn a_verified_launch_off_the_allow_list_is_refused() {
        let ca = SelfSignedCa::new(TRUST_DOMAIN).unwrap();
        let leaf = attested_leaf(&ca).await;
        for (config, what) in [
            (
                AttestationConfig::required().with_kernel_hashes(&"dd".repeat(32)),
                "kernel",
            ),
            (
                AttestationConfig::required().with_rootfs_hashes(&"dd".repeat(32)),
                "rootfs",
            ),
            (
                AttestationConfig::required().with_config_hashes(&"dd".repeat(32)),
                "config",
            ),
        ] {
            let refused = AttestationVerifier::new(config, roots(&ca))
                .admit(&TransportEvidence::ClientCert(&leaf))
                .expect_err("a measurement off the list is refused");
            assert!(refused.contains(&format!("{what} hash")), "{refused}");
        }
    }

    /// **No chain-checked source, no pass.** With no mTLS trust bundle the
    /// proxy cannot check any certificate's launch, so even a real one is
    /// refused, by name — never read as "nothing to check".
    #[tokio::test]
    async fn without_a_trust_bundle_the_requirement_refuses_by_name() {
        let ca = SelfSignedCa::new(TRUST_DOMAIN).unwrap();
        let leaf = attested_leaf(&ca).await;
        let verifier = AttestationVerifier::new(AttestationConfig::required(), LaunchRoots::Absent);
        let refused = verifier
            .admit(&TransportEvidence::ClientCert(&leaf))
            .expect_err("no roots refuses");
        assert!(refused.contains("no mTLS trust bundle"), "{refused}");
        assert!(verifier.admit(&TransportEvidence::None).is_err());
    }

    /// The assurance floor runs over the verified certificate: an L1 floor
    /// admits a CA-issued launch (base `L1Software`), and an L2 floor refuses
    /// it — residency-only tops out at L1 until the EK-manufacturer root lands.
    #[tokio::test]
    async fn the_floor_is_decided_over_the_verified_launch() {
        let ca = SelfSignedCa::new(TRUST_DOMAIN).unwrap();
        let leaf = attested_leaf(&ca).await;
        let l1 = AttestationVerifier::new(
            AttestationConfig::default().with_min_assurance(AssuranceLevel::L1Software),
            roots(&ca),
        );
        assert_eq!(l1.admit(&TransportEvidence::ClientCert(&leaf)), Ok(()));
        let l2 = AttestationVerifier::new(
            AttestationConfig::default().with_min_assurance(AssuranceLevel::L2Device),
            roots(&ca),
        );
        let refused = l2
            .admit(&TransportEvidence::ClientCert(&leaf))
            .expect_err("L2 floor refuses a software launch");
        assert!(refused.contains("below required floor"), "{refused}");
    }

    /// With the requirement off, nothing is checked (the default deployment).
    #[test]
    fn not_required_admits_without_evidence() {
        let open = AttestationVerifier::new(AttestationConfig::default(), LaunchRoots::Absent);
        assert_eq!(open.admit(&TransportEvidence::None), Ok(()));
    }

    // ── Forensic receipt cross-check (signed-agent-actions brick 2) ────────────
    use ed25519_dalek::{Signer, SigningKey};
    use nucleus_identity::AttestedSubject;
    use portcullis::mediation_receipt::MEDIATION_RECEIPT_SCHEMA_VERSION;
    use std::collections::BTreeSet;

    /// A validly-signed receipt whose signer self-claims `{assurance, backend}`.
    fn signed_receipt(sk: &SigningKey, assurance: u8, backend: &str) -> MediationReceipt {
        let mut r = MediationReceipt {
            schema_version: MEDIATION_RECEIPT_SCHEMA_VERSION,
            mediator_spiffe_id: "spiffe://demo/proxy".into(),
            session_id: "sess-1".into(),
            decision_seq: 1,
            operation: "read_file".into(),
            subject: "/etc/hosts".into(),
            verdict: "allow".into(),
            art12_record_hash: "abc".into(),
            signer_assurance: assurance,
            signer_backend: backend.into(),
            signature: String::new(),
        };
        r.signature = hex::encode(sk.sign(&r.preimage()).to_bytes());
        r
    }

    /// An independently-verified attestation — what a relying party derives itself.
    /// `key_fp` binds a specific signing key (the deep key-binding); `None` leaves
    /// the binding unestablished, as a self-measured or TPM-Name subject does.
    fn att_bound(
        backend: &'static str,
        level: AssuranceLevel,
        key_fp: Option<[u8; 32]>,
    ) -> VerifiedAttestation {
        // Synthetic — see VerifiedAttestation::for_test's own doc comment
        // (#2450 sealing; gated behind nucleus-identity's `test-helpers`
        // dev-dependency feature, enabled only for this crate's tests).
        VerifiedAttestation::for_test(
            backend,
            level,
            AttestedSubject::SelfMeasuredNode,
            key_fp,
            BTreeSet::new(),
            BTreeSet::new(),
            None,
        )
    }

    /// The common case in these tests: no key-binding declared.
    fn att(backend: &'static str, level: AssuranceLevel) -> VerifiedAttestation {
        att_bound(backend, level, None)
    }

    #[test]
    fn attested_receipt_admits_when_claim_matches_the_verified_attestation() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let r = signed_receipt(&sk, 1, "self-measured");
        let level = verify_attested_receipt(
            &r,
            &sk.verifying_key(),
            &att("self-measured", AssuranceLevel::L1Software),
        )
        .expect("a matching claim is admitted");
        assert_eq!(level, AssuranceLevel::L1Software);
    }

    /// THE load-bearing test: a validly-signed receipt inflating its assurance (an
    /// L1 signer claiming L2Device, same backend) is REJECTED against the real L1
    /// attestation — the self-claim is never believed on the signer's own word.
    /// Reverting the assurance cross-check turns this green.
    #[test]
    fn attested_receipt_rejects_an_inflated_assurance_claim() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let inflated = signed_receipt(&sk, 2, "self-measured"); // signs a claim of L2Device
        let err = verify_attested_receipt(
            &inflated,
            &sk.verifying_key(),
            &att("self-measured", AssuranceLevel::L1Software),
        )
        .unwrap_err();
        assert!(
            err.contains("assurance") && err.contains("inflated"),
            "{err}"
        );
    }

    #[test]
    fn attested_receipt_rejects_a_backend_mismatch() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let r = signed_receipt(&sk, 1, "apple-sep"); // claims a hardware backend it isn't
        let err = verify_attested_receipt(
            &r,
            &sk.verifying_key(),
            &att("self-measured", AssuranceLevel::L1Software),
        )
        .unwrap_err();
        assert!(err.contains("backend"), "{err}");
    }

    /// SHA-256 of a verifying key's 32 bytes — the same encoding
    /// `verify_attested_receipt` hashes `signer_pubkey` under.
    fn key_fp(vk: &VerifyingKey) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(vk.to_bytes());
        h.finalize().into()
    }

    /// When the attestation binds THIS signing key, a receipt signed by it is
    /// admitted — the control for the substitution test below (so that test is
    /// detecting the mismatch, not a broken binding).
    #[test]
    fn attested_receipt_admits_when_the_bound_key_signed_it() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let r = signed_receipt(&sk, 1, "self-measured");
        let level = verify_attested_receipt(
            &r,
            &sk.verifying_key(),
            &att_bound(
                "self-measured",
                AssuranceLevel::L1Software,
                Some(key_fp(&sk.verifying_key())),
            ),
        )
        .expect("the bound key's own receipt is admitted");
        assert_eq!(level, AssuranceLevel::L1Software);
    }

    /// **THE deep-key-binding load-bearing test.** A receipt validly signed by
    /// key K, whose `{backend, assurance}` match the attestation exactly, is still
    /// REJECTED when the attestation binds a DIFFERENT key K' — the attestation of
    /// a hardware-rooted identity cannot be borrowed by a receipt some other key
    /// signed. Both `signer_pubkey` and the receipt's signature are K's here
    /// (internally consistent), so only the subject-key binding catches it;
    /// deleting the step turns this green.
    #[test]
    fn attested_receipt_rejects_a_receipt_signed_by_a_key_the_attestation_does_not_bind() {
        let signer = SigningKey::from_bytes(&[7u8; 32]);
        let attested = SigningKey::from_bytes(&[8u8; 32]); // the key the SVID actually binds
        let r = signed_receipt(&signer, 1, "self-measured"); // internally valid under `signer`
        let err = verify_attested_receipt(
            &r,
            &signer.verifying_key(),
            &att_bound(
                "self-measured",
                AssuranceLevel::L1Software,
                Some(key_fp(&attested.verifying_key())),
            ),
        )
        .unwrap_err();
        assert!(
            err.contains("substitution") || err.contains("not the attested subject key"),
            "{err}"
        );
    }

    #[test]
    fn attested_receipt_rejects_a_wrong_signer_key() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let r = signed_receipt(&sk, 1, "self-measured");
        let other = SigningKey::from_bytes(&[9u8; 32]).verifying_key();
        let err = verify_attested_receipt(
            &r,
            &other,
            &att("self-measured", AssuranceLevel::L1Software),
        )
        .unwrap_err();
        assert!(err.contains("signature"), "{err}");
    }
}
