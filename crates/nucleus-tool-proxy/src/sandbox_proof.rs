#![allow(clippy::disallowed_types)] // #1216 exempt: TLS cert loading at startup
//! Cryptographic sandbox proof verification.
//!
//! Tool-proxy refuses to start unless it can cryptographically prove it's
//! running inside a managed sandbox. There is no dev override — no escape hatch.
//!
//! # Two-Tier Proof Hierarchy
//!
//! 1. **Attested** (Firecracker): SVID cert with TCG DICE extension containing
//!    kernel/rootfs/config hashes, AND a chain to the node's CA (the trust
//!    bundle). Unforgeable: requires host CA + vsock. Held as a
//!    [`VerifiedLaunch`], which only the chain check can mint.
//! 2. **SpiffeIdentity**: an SVID without the attestation extension, from the
//!    identity files the launcher wrote (the node's container and local
//!    drivers, and the host-tier launchers' minted identity,
//!    `nucleus_identity::pod_files`) or from the SPIRE Workload API.
//!
//! Verification proceeds tier 1 → tier 2. If neither succeeds, the process
//! exits with a fatal error.
//!
//! # The tier that is gone (#2446 step 3)
//!
//! A third tier, `OrchestratorToken`, accepted an HMAC-SHA256 token the node
//! minted with the shared `--auth-secret`. It proved only that the launcher
//! held a secret it also handed to the proxy, on an argv or in an environment
//! the agent could read. Every launcher now writes an identity instead, so the
//! tier, its token (`NUCLEUS_SANDBOX_TOKEN`) and its key are deleted rather
//! than kept as a fallback. A token that still arrives is named at startup and
//! proves nothing ([`RETIRED_SANDBOX_TOKEN_ENV`]).

use std::path::{Path, PathBuf};

use nucleus_identity::TrustBundle;
use tracing::{debug, error, info, warn};

use crate::attestation::AttestationInfo;

/// Evidence that this process was launched as a measured microVM by the node
/// that issued its identity.
///
/// # The defect this type exists to make unwritable (2026-09-29)
///
/// `try_svid_proof` used to return `SandboxProof::Attested` for ANY certificate
/// that carried the launch-attestation extension (OID 1.3.6.1.4.1.57212.1.1).
/// It parsed the extension and never asked who signed the certificate. A
/// self-signed leaf with that OID — made in a few lines of `rcgen` by anyone —
/// read as tier 1, and the tier-1 claim is the one that is allowed to mean "the
/// executor is inside a VM". The measurement is only worth what the signature
/// over it is worth, and nothing checked the signature.
///
/// So the claim is now a value with a private constructor (ADR 0007 C-1),
/// minted by the one function that performs the check (C-2):
/// [`VerifiedLaunch::verify`] succeeds only when the leaf chains to the node's
/// CA in the trust bundle guest-init exports as `NUCLEUS_IDENTITY_TRUST_BUNDLE`
/// AND carries a parseable launch claim. `SandboxProof::Attested` holds one, so
/// an `Attested` that skipped the chain check does not typecheck.
///
/// Not `Clone`: it is evidence about this process, held once in `AppState`
/// behind an `Arc`, and there is no second owner that needs a copy. Not
/// `#[must_use]`: it is a standing fact for the life of the process, never
/// spent, so it is not a one-shot right and carries no validity interval.
#[derive(Debug)]
pub struct VerifiedLaunch {
    spiffe_id: String,
    kernel_hash: String,
    rootfs_hash: String,
    config_hash: String,
}

impl VerifiedLaunch {
    /// The only constructor. Both halves are required, in this order: a
    /// launch claim on a certificate the node did not sign is the forgery, not
    /// a weaker form of the real thing.
    ///
    /// The check is `nucleus_identity::VerifiedLaunch::verify`, the one decider
    /// every relying party calls (ADR 0007 G-1, ADR 0016 D1); this only shapes
    /// its result for the boot log.
    fn verify(leaf_der: &[u8], trust_bundle: &TrustBundle) -> Result<Self, SandboxProofError> {
        let verified = nucleus_identity::VerifiedLaunch::verify(leaf_der, trust_bundle)
            .map_err(|e| SandboxProofError::LaunchUnverified(e.to_string()))?;
        let info = AttestationInfo::from(verified.launch());
        Ok(Self {
            spiffe_id: verified.spiffe_id().to_string(),
            kernel_hash: info.kernel_hash,
            rootfs_hash: info.rootfs_hash,
            config_hash: info.config_hash,
        })
    }

    /// The workload identity the verified certificate names.
    pub fn spiffe_id(&self) -> &str {
        &self.spiffe_id
    }
}

/// Whether a leaf carries the launch-attestation extension at all. Presence
/// only — what it is worth is [`VerifiedLaunch::verify`]'s question.
fn claims_launch(cert: &x509_parser::prelude::X509Certificate<'_>) -> bool {
    cert.extensions()
        .iter()
        .any(|ext| ext.oid.as_bytes() == nucleus_identity::oid::OID_NUCLEUS_ATTESTATION_BYTES)
}

/// Cryptographic proof that this process is running inside a managed sandbox.
#[derive(Debug)]
#[allow(dead_code)] // Fields read via Display impl and tests; future consumers will use them.
pub enum SandboxProof {
    /// Tier 1: SVID certificate with TCG DICE launch attestation, verified to
    /// chain to the node's CA.
    Attested(VerifiedLaunch),
    /// Tier 2: an SVID with no attestation extension, from identity files or
    /// the SPIRE Workload API.
    SpiffeIdentity { spiffe_id: String },
}

impl SandboxProof {
    /// The containment the executor may attest, decided here and nowhere else.
    ///
    /// `pod_mgmt::build_runtime` used to hardcode `Unsandboxed` for every pod,
    /// with a TODO to derive it from this proof. Inside a Firecracker guest the
    /// executor therefore attested `localhost()` isolation, and a policy with
    /// `minimum_isolation = microvm()` refused every command in the one place
    /// it could have been honoured. The hardcode was honest only because the
    /// tier-1 check above it was not; with `VerifiedLaunch` minted by the chain
    /// check, tier 1 is the claim a microVM boundary needs.
    ///
    /// Tier 2 proves a managed launch, not a VM boundary, so it stays
    /// `Unsandboxed`. No `_ =>` (ADR 0007 B): a new tier must say what it attests.
    pub fn containment(&self) -> nucleus::ContainmentMode {
        match self {
            SandboxProof::Attested(_) => nucleus::ContainmentMode::MicroVM,
            SandboxProof::SpiffeIdentity { .. } => nucleus::ContainmentMode::Unsandboxed,
        }
    }

    /// Human-readable tier label for logging and health endpoints.
    pub fn tier_label(&self) -> &'static str {
        match self {
            SandboxProof::Attested(_) => "attested",
            SandboxProof::SpiffeIdentity { .. } => "spiffe-identity",
        }
    }

    /// Numeric tier for ordering (1 = strongest).
    pub fn tier(&self) -> u8 {
        match self {
            SandboxProof::Attested(_) => 1,
            SandboxProof::SpiffeIdentity { .. } => 2,
        }
    }
}

impl std::fmt::Display for SandboxProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // The measurements go in the boot log: which kernel and rootfs the
            // node vouched for is what an operator needs to know when tier 1 holds.
            SandboxProof::Attested(launch) => write!(
                f,
                "tier=1/attested spiffe_id={} kernel={} rootfs={} config={}",
                launch.spiffe_id(),
                launch.kernel_hash,
                launch.rootfs_hash,
                launch.config_hash
            ),
            SandboxProof::SpiffeIdentity { spiffe_id } => {
                write!(f, "tier=2/spiffe-identity spiffe_id={spiffe_id}")
            }
        }
    }
}

/// Configuration for sandbox proof verification, assembled from CLI args and env vars.
pub struct SandboxProofConfig {
    /// Path to an identity certificate (--identity-cert or --tls-cert).
    pub identity_cert_path: Option<PathBuf>,
    /// The node's CA root (--identity-trust-bundle or --trust-bundle). A
    /// certificate's launch claim is tier 1 only if it chains to this; without
    /// it a launch claim cannot be checked and is refused, never assumed.
    pub trust_bundle_path: Option<PathBuf>,
    /// SPIRE Workload API socket path (--spire-socket or SPIFFE_ENDPOINT_SOCKET).
    pub spire_socket: Option<String>,
}

/// The environment variable the deleted tier-3 token rode (#2446 step 3).
///
/// A node from a release before the deletion still sets it on every container
/// pod, beside the identity files that are the proof now, so its presence is
/// not refused: it is named on stderr and never read. It proves nothing,
/// because nothing in this process holds a key to check it with.
pub const RETIRED_SANDBOX_TOKEN_ENV: &str = "NUCLEUS_SANDBOX_TOKEN";

/// The line [`RETIRED_SANDBOX_TOKEN_ENV`] gets when it is set, or `None`.
pub fn retired_token_notice(value: Option<&str>) -> Option<String> {
    value.filter(|v| !v.is_empty()).map(|_| {
        format!(
            "{RETIRED_SANDBOX_TOKEN_ENV} is set, but the orchestrator-token tier it proved is \
             deleted (#2446 step 3); it is ignored. The sandbox proof is the identity \
             certificate (NUCLEUS_IDENTITY_CERT) or SPIRE"
        )
    })
}

/// Errors during sandbox proof verification.
#[derive(Debug)]
pub enum SandboxProofError {
    /// No proof mechanism succeeded — process must exit.
    NakedProcess(String),
    /// Certificate file could not be read.
    CertReadError(String),
    /// Certificate could not be parsed.
    CertParseError(String),
    /// A certificate claimed a measured launch that could not be verified:
    /// no trust bundle, a chain to some other CA, or no parseable claim.
    LaunchUnverified(String),
}

impl std::fmt::Display for SandboxProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SandboxProofError::NakedProcess(msg) => {
                write!(f, "FATAL: naked process detected — {msg}")
            }
            SandboxProofError::CertReadError(msg) => write!(f, "cert read error: {msg}"),
            SandboxProofError::CertParseError(msg) => write!(f, "cert parse error: {msg}"),
            SandboxProofError::LaunchUnverified(msg) => {
                write!(f, "launch attestation unverified: {msg}")
            }
        }
    }
}

impl std::error::Error for SandboxProofError {}

/// Verify that this process is running inside a managed sandbox.
///
/// Tries each tier in order (strongest first). If none succeed,
/// returns `SandboxProofError::NakedProcess` and the process must exit.
pub async fn verify_sandbox(
    config: &SandboxProofConfig,
) -> Result<SandboxProof, SandboxProofError> {
    // Tier 1 & 2: Try SVID certificate proof
    if let Some(ref cert_path) = config.identity_cert_path {
        match try_svid_proof(cert_path, config.trust_bundle_path.as_deref()).await {
            Ok(proof) => {
                info!(containment = ?proof.containment(), "sandbox proof established: {proof}");
                return Ok(proof);
            }
            // A forged or unverifiable launch claim is worth saying out loud:
            // it is either a misconfigured guest or someone trying tier 1.
            Err(e @ SandboxProofError::LaunchUnverified(_)) => {
                warn!("SVID launch claim refused: {e}");
            }
            Err(e) => {
                debug!("SVID proof not available: {e}");
            }
        }
    }

    // Tier 2 fallback: Try SPIRE Workload API socket
    if let Some(ref socket_path) = config.spire_socket {
        match try_spire_proof(socket_path).await {
            Ok(proof) => {
                info!(containment = ?proof.containment(), "sandbox proof established: {proof}");
                return Ok(proof);
            }
            Err(e) => {
                debug!("SPIRE proof not available: {e}");
            }
        }
    }

    // No proof mechanism succeeded — fatal.
    let msg = build_naked_process_message(config);
    error!("{msg}");
    Err(SandboxProofError::NakedProcess(msg))
}

/// Try to establish proof from an SVID certificate file.
///
/// Returns Tier 1 (Attested) if the cert carries a TCG DICE attestation
/// extension AND chains to `trust_bundle_path` — [`VerifiedLaunch::verify`]
/// decides both. A launch claim that does not verify is an `Err`, not a
/// downgrade to Tier 2: a certificate asserting a measurement nobody signed is
/// not a weaker proof, it is a false one. Returns Tier 2 (SpiffeIdentity) if
/// the cert has a SPIFFE ID and makes no launch claim.
async fn try_svid_proof(
    cert_path: &Path,
    trust_bundle_path: Option<&Path>,
) -> Result<SandboxProof, SandboxProofError> {
    let pem_data = tokio::fs::read(cert_path)
        .await
        .map_err(|e| SandboxProofError::CertReadError(format!("{}: {e}", cert_path.display())))?;

    // Extract DER from PEM
    let der = decode_pem_to_der(&pem_data)
        .map_err(|e| SandboxProofError::CertParseError(format!("PEM decode: {e}")))?;

    // Parse X.509 certificate
    use x509_parser::prelude::*;
    let (_, cert) = X509Certificate::from_der(&der)
        .map_err(|e| SandboxProofError::CertParseError(format!("X.509 parse: {e}")))?;

    // Extract SPIFFE ID from SAN
    let spiffe_id = extract_spiffe_id(&cert)
        .ok_or_else(|| SandboxProofError::CertParseError("no SPIFFE ID in SAN".to_string()))?;

    if !claims_launch(&cert) {
        // SPIFFE ID but no attestation → Tier 2
        return Ok(SandboxProof::SpiffeIdentity { spiffe_id });
    }

    let bundle_path = trust_bundle_path.ok_or_else(|| {
        SandboxProofError::LaunchUnverified(
            "certificate claims a measured launch but no trust bundle \
             (--identity-trust-bundle / --trust-bundle) was given to verify it against"
                .to_string(),
        )
    })?;
    let bundle_pem = tokio::fs::read_to_string(bundle_path)
        .await
        .map_err(|e| SandboxProofError::CertReadError(format!("{}: {e}", bundle_path.display())))?;
    let bundle = TrustBundle::from_pem(&bundle_pem)
        .map_err(|e| SandboxProofError::CertParseError(format!("trust bundle: {e}")))?;
    VerifiedLaunch::verify(&der, &bundle).map(SandboxProof::Attested)
}

/// Try to establish proof via SPIRE Workload API socket.
///
/// When the `spire` feature is enabled, this connects to the SPIRE Agent's
/// Workload API and fetches a real X.509 SVID, extracting the authenticated
/// SPIFFE ID. This is the production path — the SPIRE Agent attests the
/// workload's identity through platform-specific attestors.
///
/// Without the `spire` feature, falls back to socket existence check only.
#[cfg(feature = "spire")]
async fn try_spire_proof(socket_path: &str) -> Result<SandboxProof, SandboxProofError> {
    use nucleus_identity::{CaClient, SpireCaClient};
    use x509_parser::prelude::*;

    // Verify the socket exists before attempting connection
    let path = std::path::Path::new(socket_path);
    if !path.exists() {
        return Err(SandboxProofError::CertReadError(format!(
            "SPIRE socket not found: {socket_path}"
        )));
    }

    // Normalize socket path to SPIFFE endpoint format (unix:<path>)
    let endpoint = if socket_path.starts_with("unix:") {
        socket_path.to_string()
    } else {
        format!("unix:{socket_path}")
    };

    info!(endpoint = %endpoint, "connecting to SPIRE Workload API for SVID fetch");

    // Connect to SPIRE Agent and fetch SVID
    let ca = SpireCaClient::connect_to(&endpoint).await.map_err(|e| {
        SandboxProofError::CertReadError(format!("failed to connect to SPIRE Agent: {e}"))
    })?;

    let svid = ca.fetch_svid().await.map_err(|e| {
        SandboxProofError::CertParseError(format!("failed to fetch SVID from SPIRE: {e}"))
    })?;

    let spiffe_id = svid.identity().to_spiffe_uri();
    info!(spiffe_id = %spiffe_id, "SPIRE SVID fetched successfully");

    // Check for attestation extension in the leaf certificate (Tier 1 upgrade).
    // Same checker as the file path: the claim counts only if the leaf chains
    // to the bundle the SPIRE agent serves alongside it.
    let leaf_der = svid.leaf().der();
    if let Ok((_, cert)) = X509Certificate::from_der(leaf_der)
        && claims_launch(&cert)
    {
        return VerifiedLaunch::verify(leaf_der, ca.trust_bundle()).map(SandboxProof::Attested);
    }

    // SVID without attestation extension → Tier 2
    Ok(SandboxProof::SpiffeIdentity { spiffe_id })
}

/// Fallback when `spire` feature is not enabled.
///
/// Checks socket existence only. The SPIFFE ID is hardcoded because we
/// cannot fetch a real SVID without the SPIRE client library.
#[cfg(not(feature = "spire"))]
async fn try_spire_proof(socket_path: &str) -> Result<SandboxProof, SandboxProofError> {
    let path = std::path::Path::new(socket_path);
    if !path.exists() {
        return Err(SandboxProofError::CertReadError(format!(
            "SPIRE socket not found: {socket_path}"
        )));
    }

    warn!(
        "SPIRE socket found at {socket_path} but `spire` feature is not enabled; \
         using socket existence as proof without fetching a real SVID. \
         Enable the `spire` feature for production use."
    );

    let spiffe_id = "spiffe://nucleus.local/workload/tool-proxy".to_string();
    Ok(SandboxProof::SpiffeIdentity { spiffe_id })
}

/// Extract SPIFFE ID from X.509 certificate SAN extension.
fn extract_spiffe_id(cert: &x509_parser::prelude::X509Certificate<'_>) -> Option<String> {
    // One validator for the whole repo: the local SAN loop this replaced took
    // the first `spiffe://` entry, so a certificate naming two identities was
    // resolved by DER order rather than refused.
    nucleus_identity::spiffe_uri_from_parsed_svid(cert).ok()
}

/// Decode the first PEM block into DER bytes.
fn decode_pem_to_der(pem_data: &[u8]) -> Result<Vec<u8>, String> {
    let pem_str = std::str::from_utf8(pem_data).map_err(|e| format!("invalid UTF-8: {e}"))?;
    let parsed = pem::parse(pem_str).map_err(|e| format!("PEM parse error: {e}"))?;
    Ok(parsed.into_contents())
}

fn build_naked_process_message(config: &SandboxProofConfig) -> String {
    let mut reasons = Vec::new();
    if config.identity_cert_path.is_none() {
        reasons.push("no identity cert (--identity-cert or --tls-cert)");
    }
    if config.spire_socket.is_none() {
        reasons.push("no SPIRE socket (--spire-socket or SPIFFE_ENDPOINT_SOCKET)");
    }
    format!(
        "no sandbox proof available. Tried both tiers. Missing: {}. \
         Tool-proxy will not start outside a managed sandbox.",
        reasons.join("; ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use nucleus_identity::{CaClient, CsrOptions, Identity, LaunchAttestation, SelfSignedCa};

    const TRUST_DOMAIN: &str = "nucleus.local";

    fn launch() -> LaunchAttestation {
        LaunchAttestation::from_hashes([1u8; 32], [2u8; 32], [3u8; 32])
    }

    /// A leaf the way the node issues one: signed by `ca`, launch claim embedded.
    async fn attested_leaf(ca: &SelfSignedCa) -> String {
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
        .chain_pem()
    }

    /// A leaf the node issues without a launch claim — tier 2.
    async fn plain_leaf(ca: &SelfSignedCa) -> String {
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
        .chain_pem()
    }

    /// The forgery: a self-signed leaf carrying the launch OID and a
    /// well-formed measurement. Anyone can make this; before 2026-09-29 it
    /// read as tier 1.
    fn forged_leaf() -> String {
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
        params.self_signed(&key).unwrap().pem()
    }

    fn bundle_pem(ca: &SelfSignedCa) -> String {
        ca.trust_bundle()
            .roots()
            .iter()
            .map(|c| c.to_pem().to_string())
            .collect()
    }

    fn write(dir: &tempfile::TempDir, name: &str, contents: &str) -> PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }

    /// The defect (red on the pre-fix code, which returned `Attested` here):
    /// a self-signed certificate carrying the launch OID is not tier 1, and so
    /// cannot put the executor in `MicroVM`. Checked with the node's real
    /// bundle present, so the refusal is the chain and not a missing file.
    #[tokio::test]
    async fn a_self_signed_launch_claim_is_not_attested() {
        let dir = tempfile::tempdir().unwrap();
        let node_ca = SelfSignedCa::new(TRUST_DOMAIN).unwrap();
        let cert = write(&dir, "svid.pem", &forged_leaf());
        let bundle = write(&dir, "bundle.pem", &bundle_pem(&node_ca));

        let proof = try_svid_proof(&cert, Some(&bundle)).await;
        assert!(
            matches!(proof, Err(SandboxProofError::LaunchUnverified(_))),
            "a self-signed launch claim must be refused, got {proof:?}"
        );
        assert!(
            !proof.is_ok_and(|p| p.containment() == nucleus::ContainmentMode::MicroVM),
            "a forged launch claim must never attest a microVM"
        );
    }

    /// No bundle means the claim cannot be checked. "Could not look" is not
    /// "looked and it was fine" (ADR 0007 A): refused, not assumed.
    #[tokio::test]
    async fn a_launch_claim_without_a_bundle_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let ca = SelfSignedCa::new(TRUST_DOMAIN).unwrap();
        let cert = write(&dir, "svid.pem", &attested_leaf(&ca).await);
        let proof = try_svid_proof(&cert, None).await;
        assert!(
            matches!(proof, Err(SandboxProofError::LaunchUnverified(_))),
            "got {proof:?}"
        );
    }

    /// The satisfy half: a leaf the node CA signed, with the launch claim,
    /// verified against that CA's bundle, IS tier 1 and attests `MicroVM`,
    /// and the measurements it carries are the ones the node embedded.
    #[tokio::test]
    async fn a_launch_claim_chained_to_the_node_ca_is_attested_microvm() {
        let dir = tempfile::tempdir().unwrap();
        let ca = SelfSignedCa::new(TRUST_DOMAIN).unwrap();
        let cert = write(&dir, "svid.pem", &attested_leaf(&ca).await);
        let bundle = write(&dir, "bundle.pem", &bundle_pem(&ca));

        let proof = try_svid_proof(&cert, Some(&bundle)).await.unwrap();
        assert_eq!(proof.containment(), nucleus::ContainmentMode::MicroVM);
        let SandboxProof::Attested(launch) = &proof else {
            panic!("expected Attested, got {proof:?}");
        };
        assert_eq!(launch.spiffe_id(), "spiffe://nucleus.local/ns/pods/sa/p1");
        assert_eq!(launch.kernel_hash, hex::encode([1u8; 32]));
    }

    /// A real node-issued leaf, checked against a DIFFERENT node's bundle, is
    /// refused: the claim is bound to the CA that signed it.
    #[tokio::test]
    async fn a_launch_claim_chained_to_another_ca_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let issuing = SelfSignedCa::new(TRUST_DOMAIN).unwrap();
        let other = SelfSignedCa::new(TRUST_DOMAIN).unwrap();
        let cert = write(&dir, "svid.pem", &attested_leaf(&issuing).await);
        let bundle = write(&dir, "bundle.pem", &bundle_pem(&other));

        let proof = try_svid_proof(&cert, Some(&bundle)).await;
        assert!(
            matches!(proof, Err(SandboxProofError::LaunchUnverified(_))),
            "got {proof:?}"
        );
    }

    /// End to end through `verify_sandbox`: a forged claim and nothing else
    /// is a naked process (exit 78), not a tier-1 proxy.
    #[tokio::test]
    async fn a_forged_claim_alone_is_a_naked_process() {
        let dir = tempfile::tempdir().unwrap();
        let node_ca = SelfSignedCa::new(TRUST_DOMAIN).unwrap();
        let config = SandboxProofConfig {
            identity_cert_path: Some(write(&dir, "svid.pem", &forged_leaf())),
            trust_bundle_path: Some(write(&dir, "bundle.pem", &bundle_pem(&node_ca))),
            spire_socket: None,
        };
        assert!(matches!(
            verify_sandbox(&config).await,
            Err(SandboxProofError::NakedProcess(_))
        ));
    }

    /// Tier 2 proves a managed launch, not a VM boundary.
    #[tokio::test]
    async fn the_spiffe_tier_is_unsandboxed() {
        let dir = tempfile::tempdir().unwrap();
        let ca = SelfSignedCa::new(TRUST_DOMAIN).unwrap();
        let cert = write(&dir, "svid.pem", &plain_leaf(&ca).await);
        let spiffe = try_svid_proof(&cert, None).await.unwrap();
        assert_eq!(spiffe.tier(), 2);
        assert_eq!(spiffe.containment(), nucleus::ContainmentMode::Unsandboxed);
    }

    #[tokio::test]
    async fn test_tier_labels() {
        let dir = tempfile::tempdir().unwrap();
        let ca = SelfSignedCa::new(TRUST_DOMAIN).unwrap();
        let cert = write(&dir, "svid.pem", &attested_leaf(&ca).await);
        let bundle = write(&dir, "bundle.pem", &bundle_pem(&ca));
        let attested = try_svid_proof(&cert, Some(&bundle)).await.unwrap();
        assert_eq!(attested.tier_label(), "attested");
        assert_eq!(attested.tier(), 1);

        let spiffe = SandboxProof::SpiffeIdentity {
            spiffe_id: "spiffe://example/wl".into(),
        };
        assert_eq!(spiffe.tier_label(), "spiffe-identity");
        assert_eq!(spiffe.tier(), 2);
        assert!(format!("{spiffe}").contains("tier=2/spiffe-identity"));
    }

    /// With no certificate and no SPIRE socket the process is naked, and the
    /// refusal names what is missing. It no longer offers the deleted token as
    /// a way in (#2446 step 3).
    #[tokio::test]
    async fn test_naked_process_rejected() {
        let config = SandboxProofConfig {
            identity_cert_path: None,
            trust_bundle_path: None,
            spire_socket: None,
        };

        let result = verify_sandbox(&config).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            SandboxProofError::NakedProcess(msg) => {
                assert!(msg.contains("no sandbox proof"));
                assert!(msg.contains("no identity cert"));
                assert!(msg.contains("no SPIRE socket"));
                assert!(!msg.contains(RETIRED_SANDBOX_TOKEN_ENV), "{msg}");
            }
            other => panic!("expected NakedProcess, got: {other}"),
        }
    }

    /// A token from a node that still sets one is named, and an absent or
    /// empty one says nothing.
    #[test]
    fn a_retired_token_is_named_and_proves_nothing() {
        let notice = retired_token_notice(Some("sandbox-proof.pod.hash.1.ab")).unwrap();
        for needle in [RETIRED_SANDBOX_TOKEN_ENV, "#2446", "ignored"] {
            assert!(notice.contains(needle), "missing {needle:?} in {notice}");
        }
        assert_eq!(retired_token_notice(None), None);
        assert_eq!(retired_token_notice(Some("")), None);
    }
}
