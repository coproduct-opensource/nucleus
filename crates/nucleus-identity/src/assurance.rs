//! Normalized assurance for heterogeneous attestation roots (North Star C9 fabric).
//!
//! Today nucleus has exactly one attestation root: the node's own SHA-256
//! measurement of the kernel+rootfs it launched, signed by the node's CA key
//! ([`LaunchAttestation`]). That is first-party *software* attestation — there is no
//! hardware root. This module introduces the seam that lets other roots (TPM DevID,
//! Apple App Attest, cloud instance identity, …) plug in behind one honest,
//! normalized result type.
//!
//! Two design rules make this safe to build on:
//!
//! 1. **Backends verify genuineness only.** A backend answers "is this genuine and
//!    what does it prove?" — never tenancy, authorization, or policy. Those live
//!    above the fabric (the managed control plane), not in a root.
//! 2. **The result carries what it does NOT prove.** [`VerifiedAttestation`] ships a
//!    closed `not_proven` set so a relying party physically cannot read more into an
//!    attestation than the backend established — over-reading is unsayable, not
//!    merely undocumented.
//!
//! This is the *relying-party* seam: it normalizes verification of the attestation
//! carried by a served SVID. Roots whose genuineness check needs I/O at *issuance*
//! (e.g. contacting Apple's App Attest servers) verify there and embed the result in
//! the SVID; by the time a relying party reads the SVID the check is local, so this
//! trait is intentionally synchronous.

use std::collections::BTreeSet;

use crate::attestation::{verify_attested_svid, AttestationRequirements, LaunchAttestation};
use crate::Result;

/// Normalized assurance level, comparable across attestation roots.
///
/// The level is *derived* for policy convenience (e.g. "require ≥ `L2Device`");
/// [`VerifiedAttestation::proves`] / `not_proven` are the authoritative ground truth.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum AssuranceLevel {
    /// No hardware; bearer / OIDC. Baseline, for migration.
    L0Bearer = 0,
    /// Non-exportable hardware key + single-vendor *online* attestation, app/instance
    /// scope, no stable device identity — or first-party *software* measurement.
    L1Software = 1,
    /// Hardware key + *stable device identity*, manufacturer-CA rooted,
    /// offline-verifiable (e.g. TPM DevID, Apple Managed Device Attestation).
    L2Device = 2,
    /// `L2Device` + measured boot / runtime state (PCR quote, TEE quote).
    L3MeasuredBoot = 3,
}

impl AssuranceLevel {
    /// The level as its ordinal, for wire encoding and comparison.
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Closed vocabulary of what an attestation can (or cannot) prove.
///
/// A relying party checks membership in [`VerifiedAttestation::proves`]; it must not
/// infer anything outside this set. New variants are added deliberately, never
/// inferred.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum Claim {
    /// The launched artifact matches a known measurement (kernel/rootfs/config).
    UnmodifiedArtifact,
    /// The private key cannot be exported from where it was generated.
    KeyNonExportable,
    /// The signing key is bound to genuine vendor hardware (TPM EK / SEP).
    HardwareRootedKey,
    /// A persistent device / instance identifier is attested.
    StableDeviceIdentity,
    /// Boot / runtime state is measured (PCRs / TEE quote).
    MeasuredBoot,
    /// The attestation is continuously refreshed (liveness).
    ContinuousLiveness,
}

/// What the backend names as the attested subject (backend-specific, typed).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttestedSubject {
    /// The nucleus node's self-measurement of the artifact it launched.
    SelfMeasuredNode,
    // Future roots land here as typed variants, e.g.:
    //   TpmDevice { ek_pub_sha256: [u8; 32], devid_subject: String },
    //   AppleApp  { team_id: String, bundle_id: String },
    //   CloudInstance { provider: String, instance_id: String },
}

/// The normalized, honest result every attestation backend produces.
///
/// `not_proven` is carried deliberately: it is what makes over-reading unsayable
/// rather than merely undocumented.
#[derive(Clone, Debug)]
pub struct VerifiedAttestation {
    /// Stable backend identifier (e.g. `"self-measured"`).
    pub backend: &'static str,
    /// Normalized assurance this result carries.
    pub assurance: AssuranceLevel,
    /// What the backend names as the attested subject.
    pub subject: AttestedSubject,
    /// Claims the backend affirmatively established.
    pub proves: BTreeSet<Claim>,
    /// Claims the backend explicitly could NOT establish.
    pub not_proven: BTreeSet<Claim>,
    /// The launch measurement, when this backend is measurement-based.
    pub launch: Option<LaunchAttestation>,
}

impl VerifiedAttestation {
    /// True iff the backend affirmatively proved `claim`.
    pub fn proves(&self, claim: Claim) -> bool {
        self.proves.contains(&claim)
    }

    /// True iff the backend explicitly could NOT prove `claim`. A relying party that
    /// needs `claim` must treat this as a hard "no", never a "maybe".
    pub fn cannot_prove(&self, claim: Claim) -> bool {
        self.not_proven.contains(&claim)
    }

    /// The normalized assurance level.
    pub fn assurance(&self) -> AssuranceLevel {
        self.assurance
    }
}

/// A pluggable attestation root, verified from a served SVID.
///
/// Each backend verifies the attestation carried by an SVID's leaf certificate and
/// returns a normalized [`VerifiedAttestation`]. Verification is *genuineness only*
/// — it must not consult tenancy, authorization, or policy.
pub trait SvidAttestationBackend: Send + Sync {
    /// Stable backend identifier.
    fn id(&self) -> &'static str;

    /// The normalized assurance this backend delivers.
    fn assurance(&self) -> AssuranceLevel;

    /// Verify the attestation carried by a served SVID chain (leaf PEM).
    ///
    /// `require_attestation` makes an absent attestation a hard error (fail-closed);
    /// when cleared, an absent attestation yields `Ok(None)`. A present-but-drifted
    /// measurement is always an `Err`.
    fn verify_svid(
        &self,
        chain_pem: &str,
        requirements: &AttestationRequirements,
        require_attestation: bool,
    ) -> Result<Option<VerifiedAttestation>>;
}

/// The root nucleus ships today: the node's own SHA-256 measurement of the artifact
/// it launched, signed by the node's CA key.
///
/// # Trust boundary
///
/// This is first-party **software** launch attestation. There is no hardware root —
/// no TPM/SEV-SNP/TDX quote, no UDS-in-ROM DICE identity — so it proves only
/// [`Claim::UnmodifiedArtifact`], conditional on trusting the node's key, and
/// explicitly does not prove a hardware-rooted key, a stable device identity,
/// measured boot, or continuous liveness.
#[derive(Debug, Clone, Copy, Default)]
pub struct SelfMeasuredBackend;

impl SelfMeasuredBackend {
    /// The claims a self-measured software attestation can / cannot establish.
    fn claim_profile() -> (BTreeSet<Claim>, BTreeSet<Claim>) {
        let proves = BTreeSet::from([Claim::UnmodifiedArtifact]);
        let not_proven = BTreeSet::from([
            Claim::KeyNonExportable,
            Claim::HardwareRootedKey,
            Claim::StableDeviceIdentity,
            Claim::MeasuredBoot,
            Claim::ContinuousLiveness,
        ]);
        (proves, not_proven)
    }
}

impl SvidAttestationBackend for SelfMeasuredBackend {
    fn id(&self) -> &'static str {
        "self-measured"
    }

    fn assurance(&self) -> AssuranceLevel {
        AssuranceLevel::L1Software
    }

    fn verify_svid(
        &self,
        chain_pem: &str,
        requirements: &AttestationRequirements,
        require_attestation: bool,
    ) -> Result<Option<VerifiedAttestation>> {
        match verify_attested_svid(chain_pem, requirements, require_attestation)? {
            Some(launch) => {
                let (proves, not_proven) = Self::claim_profile();
                Ok(Some(VerifiedAttestation {
                    backend: self.id(),
                    assurance: self.assurance(),
                    subject: AttestedSubject::SelfMeasuredNode,
                    proves,
                    not_proven,
                    launch: Some(launch),
                }))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CaClient, CsrOptions, Identity, SelfSignedCa};
    use std::time::Duration;

    async fn mint_chain(attested: bool) -> (String, LaunchAttestation) {
        let ca = SelfSignedCa::new("test.local").unwrap();
        let identity = Identity::for_pod("test.local", "pod-1");
        let cs = CsrOptions::new(identity.to_spiffe_uri())
            .generate()
            .unwrap();
        let att = LaunchAttestation::from_hashes([7u8; 32], [8u8; 32], [9u8; 32]);
        let cert = if attested {
            ca.sign_attested_csr(
                cs.csr(),
                cs.private_key(),
                &identity,
                Duration::from_secs(3600),
                &att,
            )
            .await
            .unwrap()
        } else {
            ca.sign_csr(
                cs.csr(),
                cs.private_key(),
                &identity,
                Duration::from_secs(3600),
            )
            .await
            .unwrap()
        };
        (cert.chain_pem(), att)
    }

    #[test]
    fn assurance_levels_order_and_encode() {
        assert!(AssuranceLevel::L0Bearer < AssuranceLevel::L2Device);
        assert!(AssuranceLevel::L3MeasuredBoot > AssuranceLevel::L1Software);
        assert_eq!(AssuranceLevel::L1Software.as_u8(), 1);
    }

    #[tokio::test]
    async fn self_measured_backend_normalizes_and_carries_not_proven() {
        let backend = SelfMeasuredBackend;
        let (chain, att) = mint_chain(true).await;
        let req = AttestationRequirements::exact(
            *att.kernel_hash(),
            *att.rootfs_hash(),
            *att.config_hash(),
        );

        let va = backend
            .verify_svid(&chain, &req, true)
            .expect("verify ok")
            .expect("attestation present");

        assert_eq!(va.backend, "self-measured");
        assert_eq!(va.assurance(), AssuranceLevel::L1Software);
        assert_eq!(va.subject, AttestedSubject::SelfMeasuredNode);
        // Proves exactly the artifact match…
        assert!(va.proves(Claim::UnmodifiedArtifact));
        // …and is explicit about the hardware-root gap it CANNOT close.
        assert!(va.cannot_prove(Claim::HardwareRootedKey));
        assert!(va.cannot_prove(Claim::StableDeviceIdentity));
        assert!(va.cannot_prove(Claim::MeasuredBoot));
        // proves and not_proven are disjoint (no claim is both).
        assert!(va.proves.is_disjoint(&va.not_proven));
    }

    #[tokio::test]
    async fn self_measured_backend_reds_on_drift_and_fails_closed_on_absent() {
        let backend = SelfMeasuredBackend;
        let (chain, att) = mint_chain(true).await;

        // Drift: one wrong expected hash → Err.
        let mut wrong = *att.kernel_hash();
        wrong[0] ^= 0x01;
        let drifted = AttestationRequirements::exact(wrong, *att.rootfs_hash(), *att.config_hash());
        assert!(backend.verify_svid(&chain, &drifted, true).is_err());

        // Absent + require → Err (fail-closed); absent + !require → Ok(None).
        let (plain, _) = mint_chain(false).await;
        assert!(backend
            .verify_svid(&plain, &AttestationRequirements::any(), true)
            .is_err());
        assert!(backend
            .verify_svid(&plain, &AttestationRequirements::any(), false)
            .expect("absent-not-required ok")
            .is_none());
    }
}
