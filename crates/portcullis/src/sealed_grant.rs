//! A task grant sealed into a signed certificate (ADR 0004, milestone 2).
//!
//! Milestone 1 compiled a goal into a [`TaskGrant`] a person approves once.
//! This module makes that approval **durable**: sealing mints a root
//! [`LatticeCertificate`] whose permissions are the grant's lattice plus the
//! granted effects (as `effect/` extension keys) plus three binding keys
//! (`grant/id/…`, `grant/goal/…`, `grant/repo/…`), signs it with the
//! approver's Ed25519 key, and wraps it in an [`AttenuationToken`]. The
//! sealed grant is the certificate and the readable grant side by side;
//! verification proves the two agree.
//!
//! What a verifier learns, in order:
//!
//! 1. the token's root key is one it trusts (the approver's key, by default
//!    the local one) — an unknown signer is refused before any signature is
//!    checked;
//! 2. the certificate chain verifies (`verify_certificate`: signatures,
//!    hash chain, monotone attenuation, expiry, proof-of-possession);
//! 3. the readable grant re-lowers to exactly the signed permissions
//!    (`canonical_permissions_hash`), so no field a person reads — goal,
//!    effects, limits, expiry, repository — can be edited independently of
//!    what was signed;
//! 4. the goal digest matches the goal text (prompt playback is intact);
//! 5. optionally, the repository the grant is being reused in has the
//!    context digest it was compiled against.
//!
//! This is the `C(T) = 0` path: `nucleus run --grant FILE` asks nothing when
//! all five hold, because the person already decided. Nothing here widens
//! authority: a sealed grant carries the lattice the ceiling admitted, and a
//! certificate delegated from it can only narrow (`effect_surface`).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::certificate::canonical_permissions_hash;
use crate::task_grant::TaskGrant;
use crate::token::{AttenuationToken, TokenError};
use crate::{effect_surface, CapabilityLevel, ExtensionOperation, PermissionLattice};

#[cfg(feature = "crypto")]
use crate::certificate::LatticeCertificate;
#[cfg(feature = "crypto")]
use ring::signature::{Ed25519KeyPair, KeyPair};

/// Prefix of the extension keys that bind a certificate to the grant it
/// seals: `grant/id/<uuid>`, `grant/goal/<sha256>`, `grant/repo/<digest>`.
pub const GRANT_BINDING_MARKER: &str = "grant/";

impl TaskGrant {
    /// The permissions a sealed grant's certificate carries: the compiled
    /// lattice, every granted effect as an `effect/` key, and the binding
    /// keys. Deterministic, so a verifier recomputes it from the readable
    /// grant and compares hashes.
    pub fn sealed_permissions(&self) -> PermissionLattice {
        let mut perms = self.lattice.clone();
        effect_surface::mark_effects(&mut perms.capabilities);
        for effect in &self.can {
            effect_surface::grant_effect(&mut perms.capabilities, &effect.to_string());
        }
        for key in self.binding_keys() {
            perms
                .capabilities
                .extensions
                .insert(key, CapabilityLevel::Always);
        }
        perms
    }

    fn binding_keys(&self) -> [ExtensionOperation; 3] {
        [
            ExtensionOperation::new(format!("{GRANT_BINDING_MARKER}id/{}", self.id)),
            ExtensionOperation::new(format!("{GRANT_BINDING_MARKER}goal/{}", self.goal_digest)),
            ExtensionOperation::new(format!(
                "{GRANT_BINDING_MARKER}repo/{}",
                self.provenance.repo_context_digest
            )),
        ]
    }
}

/// A grant and the certificate that seals it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedTaskGrant {
    /// Schema version of the sealed form.
    pub version: u8,
    /// The readable grant.
    pub grant: TaskGrant,
    /// The signed certificate, self-contained with its root key.
    pub token: AttenuationToken,
}

/// Why a sealed grant was not accepted.
#[derive(Debug)]
pub enum SealedGrantError {
    /// The sealed form is a version this build does not read.
    UnsupportedVersion {
        /// The version found.
        found: u8,
    },
    /// The token's root key is not one the verifier trusts.
    UntrustedSigner {
        /// Hex of the root public key found.
        signer: String,
    },
    /// The certificate chain did not verify.
    Token(TokenError),
    /// The readable grant does not re-lower to the signed permissions.
    LatticeMismatch,
    /// The goal text does not hash to the recorded digest.
    GoalMismatch,
    /// The grant's readable expiry disagrees with the signed one.
    ExpiryMismatch,
    /// The grant was compiled against a different repository context.
    RepoMismatch {
        /// The digest the grant was compiled against.
        expected: String,
        /// The digest of the repository it is being reused in.
        actual: String,
    },
}

impl std::fmt::Display for SealedGrantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedVersion { found } => {
                write!(f, "sealed grant version {found} is not supported")
            }
            Self::UntrustedSigner { signer } => write!(
                f,
                "the grant was sealed by a key this host does not trust ({signer})"
            ),
            Self::Token(e) => write!(f, "the grant's certificate did not verify: {e}"),
            Self::LatticeMismatch => write!(
                f,
                "the readable grant does not match the signed permissions (edited after sealing?)"
            ),
            Self::GoalMismatch => write!(f, "the goal text does not match its signed digest"),
            Self::ExpiryMismatch => write!(f, "the grant's expiry does not match the signed one"),
            Self::RepoMismatch { expected, actual } => write!(
                f,
                "the repository changed since this grant was approved (compiled against {expected}, now {actual}); re-run with --goal to approve it again"
            ),
        }
    }
}

impl std::error::Error for SealedGrantError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Token(e) => Some(e),
            _ => None,
        }
    }
}

impl From<TokenError> for SealedGrantError {
    fn from(e: TokenError) -> Self {
        Self::Token(e)
    }
}

/// Marker that makes [`VerifiedGrant`] constructible only by
/// [`SealedTaskGrant::verify`] (same pattern as `VerifiedPermissions`).
#[derive(Debug, Clone)]
struct GrantSeal;

/// A sealed grant that verified: the run path accepts nothing else.
#[derive(Debug, Clone)]
pub struct VerifiedGrant {
    grant: TaskGrant,
    effective: PermissionLattice,
    signer: Vec<u8>,
    fingerprint: [u8; 32],
    approver: String,
    _seal: GrantSeal,
}

impl VerifiedGrant {
    /// The grant as sealed.
    pub fn grant(&self) -> &TaskGrant {
        &self.grant
    }

    /// The signed permissions (lattice + effect keys + binding keys).
    pub fn effective(&self) -> &PermissionLattice {
        &self.effective
    }

    /// Hex of the signer's Ed25519 public key.
    pub fn signer_hex(&self) -> String {
        hex::encode(&self.signer)
    }

    /// Hex of the certificate fingerprint.
    pub fn fingerprint_hex(&self) -> String {
        hex::encode(self.fingerprint)
    }

    /// The identity the approver sealed as.
    pub fn approver(&self) -> &str {
        &self.approver
    }
}

impl SealedTaskGrant {
    /// Current sealed-form version.
    pub const VERSION: u8 = 1;

    /// Seal `grant` as `approver`, signing with `key`. The key is both the
    /// root authority and the holder, so the same key can later delegate a
    /// narrower certificate from the sealed one.
    #[cfg(feature = "crypto")]
    pub fn seal(grant: TaskGrant, approver: String, key: &Ed25519KeyPair) -> Self {
        let cert = LatticeCertificate::mint_with_holder_key(
            grant.sealed_permissions(),
            approver,
            grant.not_after,
            None,
            key,
            key,
        );
        let token = AttenuationToken::seal(cert, key.public_key().as_ref().to_vec());
        Self {
            version: Self::VERSION,
            grant,
            token,
        }
    }

    /// Hex of the root key that sealed this grant.
    pub fn signer_hex(&self) -> String {
        hex::encode(self.token.root_public_key())
    }

    /// Verify the sealed grant at `now` against `trusted_signers` (32-byte
    /// Ed25519 public keys) and, when given, the digest of the repository
    /// context it is about to be reused in. See the module doc for the
    /// order of checks.
    #[cfg(feature = "crypto")]
    pub fn verify(
        &self,
        now: DateTime<Utc>,
        trusted_signers: &[Vec<u8>],
        repo_context_digest: Option<&str>,
    ) -> Result<VerifiedGrant, SealedGrantError> {
        if self.version != Self::VERSION {
            return Err(SealedGrantError::UnsupportedVersion {
                found: self.version,
            });
        }
        let signer = self.token.root_public_key();
        if !trusted_signers.iter().any(|k| k.as_slice() == signer) {
            return Err(SealedGrantError::UntrustedSigner {
                signer: hex::encode(signer),
            });
        }
        let verified = self.token.verify_default(now)?;
        let expected = self.grant.sealed_permissions();
        if canonical_permissions_hash(verified.effective()) != canonical_permissions_hash(&expected)
        {
            return Err(SealedGrantError::LatticeMismatch);
        }
        if TaskGrant::digest_goal(&self.grant.goal) != self.grant.goal_digest {
            return Err(SealedGrantError::GoalMismatch);
        }
        // `time.valid_until` is inside the signed lattice; the readable
        // `not_after` must be the same instant.
        if self.grant.not_after != self.grant.lattice.time.valid_until {
            return Err(SealedGrantError::ExpiryMismatch);
        }
        if let Some(actual) = repo_context_digest {
            let expected = &self.grant.provenance.repo_context_digest;
            if expected != actual {
                return Err(SealedGrantError::RepoMismatch {
                    expected: expected.clone(),
                    actual: actual.to_string(),
                });
            }
        }
        Ok(VerifiedGrant {
            grant: self.grant.clone(),
            effective: verified.effective().clone(),
            signer: signer.to_vec(),
            fingerprint: self.token.fingerprint(),
            approver: verified.root_identity().to_string(),
            _seal: GrantSeal,
        })
    }
}

#[cfg(all(test, feature = "crypto"))]
mod tests {
    use super::*;
    use crate::effect_catalog::EffectId;
    use crate::task_grant::{CompilerProvenance, GrantLimits, RiskSummary};
    use crate::{CapabilityLevel, StateRisk, WeakeningCostConfig};
    use chrono::Duration;
    use std::collections::BTreeSet;

    fn key() -> Ed25519KeyPair {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
    }

    fn pubkey(k: &Ed25519KeyPair) -> Vec<u8> {
        k.public_key().as_ref().to_vec()
    }

    fn grant() -> TaskGrant {
        let now = Utc::now();
        let not_after = now + Duration::hours(2);
        let mut lattice = PermissionLattice::restrictive();
        lattice.capabilities.run_bash = CapabilityLevel::LowRisk;
        lattice.time.valid_until = not_after;
        let restrictive = PermissionLattice::restrictive();
        let gap = WeakeningCostConfig::default().compute_gap(&restrictive, &lattice);
        let goal = "run the tests".to_string();
        TaskGrant {
            version: TaskGrant::VERSION,
            id: uuid::Uuid::new_v4(),
            goal_digest: TaskGrant::digest_goal(&goal),
            goal,
            ceiling_profile: "codegen".into(),
            can: ["fs/read-workspace", "shell/run-tests"]
                .iter()
                .map(|s| s.parse::<EffectId>().unwrap())
                .collect::<BTreeSet<_>>(),
            cannot: Vec::new(),
            limits: GrantLimits {
                max_cost_usd: rust_decimal::Decimal::new(500, 2),
                duration_secs: 7200,
                hosts: Vec::new(),
                blocked_paths: Vec::new(),
                commands: Vec::new(),
            },
            lattice,
            risk: RiskSummary {
                before: StateRisk::Safe,
                after: StateRisk::Safe,
                exposure_legs: Vec::new(),
                approval_gated: Vec::new(),
                gap,
            },
            provenance: CompilerProvenance {
                compiler: "test/0".into(),
                proposers: vec!["rules".into()],
                rules_fired: vec!["test".into()],
                repo_context_digest: "repo-digest-1".into(),
            },
            created_at: now,
            not_after,
        }
    }

    #[test]
    fn seal_then_verify_round_trips_and_carries_the_effects() {
        let k = key();
        let sealed = SealedTaskGrant::seal(grant(), "nucleus://approver/me".into(), &k);
        let json = serde_json::to_string(&sealed).unwrap();
        let back: SealedTaskGrant = serde_json::from_str(&json).unwrap();
        let v = back
            .verify(Utc::now(), &[pubkey(&k)], Some("repo-digest-1"))
            .unwrap();
        assert_eq!(v.approver(), "nucleus://approver/me");
        assert_eq!(v.signer_hex(), hex::encode(pubkey(&k)));
        let effects = effect_surface::granted_effects(&v.effective().capabilities).unwrap();
        assert_eq!(effects.len(), 2);
        assert!(effects.contains("shell/run-tests"));
        assert_eq!(
            v.effective().capabilities.run_bash,
            CapabilityLevel::LowRisk
        );
    }

    #[test]
    fn an_untrusted_signer_is_refused_before_anything_else() {
        let k = key();
        let sealed = SealedTaskGrant::seal(grant(), "me".into(), &k);
        let err = sealed
            .verify(Utc::now(), &[pubkey(&key())], None)
            .unwrap_err();
        assert!(
            matches!(err, SealedGrantError::UntrustedSigner { .. }),
            "{err}"
        );
    }

    #[test]
    fn editing_the_readable_grant_after_sealing_is_detected() {
        let k = key();
        let trusted = [pubkey(&k)];

        // A wider lattice than was signed.
        let mut sealed = SealedTaskGrant::seal(grant(), "me".into(), &k);
        sealed.grant.lattice.capabilities.git_push = CapabilityLevel::Always;
        assert!(matches!(
            sealed.verify(Utc::now(), &trusted, None).unwrap_err(),
            SealedGrantError::LatticeMismatch
        ));

        // An extra effect in `can`.
        let mut sealed = SealedTaskGrant::seal(grant(), "me".into(), &k);
        sealed
            .grant
            .can
            .insert("git/push-branch".parse::<EffectId>().unwrap());
        assert!(matches!(
            sealed.verify(Utc::now(), &trusted, None).unwrap_err(),
            SealedGrantError::LatticeMismatch
        ));

        // A different goal text under the same digest.
        let mut sealed = SealedTaskGrant::seal(grant(), "me".into(), &k);
        sealed.grant.goal = "delete everything".into();
        assert!(matches!(
            sealed.verify(Utc::now(), &trusted, None).unwrap_err(),
            SealedGrantError::GoalMismatch
        ));

        // A goal text AND digest both rewritten: the binding key no longer
        // matches the signed one.
        let mut sealed = SealedTaskGrant::seal(grant(), "me".into(), &k);
        sealed.grant.goal = "delete everything".into();
        sealed.grant.goal_digest = TaskGrant::digest_goal(&sealed.grant.goal);
        assert!(matches!(
            sealed.verify(Utc::now(), &trusted, None).unwrap_err(),
            SealedGrantError::LatticeMismatch
        ));

        // A later readable expiry than was signed.
        let mut sealed = SealedTaskGrant::seal(grant(), "me".into(), &k);
        sealed.grant.not_after += Duration::days(30);
        assert!(matches!(
            sealed.verify(Utc::now(), &trusted, None).unwrap_err(),
            SealedGrantError::ExpiryMismatch
        ));

        // The repository the grant was compiled against, rewritten.
        let mut sealed = SealedTaskGrant::seal(grant(), "me".into(), &k);
        sealed.grant.provenance.repo_context_digest = "repo-digest-2".into();
        assert!(matches!(
            sealed.verify(Utc::now(), &trusted, None).unwrap_err(),
            SealedGrantError::LatticeMismatch
        ));
    }

    #[test]
    fn a_grant_is_bound_to_the_repository_it_was_compiled_in() {
        let k = key();
        let sealed = SealedTaskGrant::seal(grant(), "me".into(), &k);
        let err = sealed
            .verify(Utc::now(), &[pubkey(&k)], Some("some-other-repo"))
            .unwrap_err();
        assert!(
            matches!(err, SealedGrantError::RepoMismatch { .. }),
            "{err}"
        );
    }

    #[test]
    fn an_expired_grant_does_not_verify() {
        let k = key();
        let sealed = SealedTaskGrant::seal(grant(), "me".into(), &k);
        let later = Utc::now() + Duration::days(1);
        let err = sealed.verify(later, &[pubkey(&k)], None).unwrap_err();
        assert!(matches!(err, SealedGrantError::Token(_)), "{err}");
    }

    #[test]
    fn a_certificate_delegated_from_a_sealed_grant_can_only_narrow() {
        use crate::certificate::SinkScope;
        let k = key();
        let sealed = SealedTaskGrant::seal(grant(), "me".into(), &k);
        let cert = sealed.token.certificate().clone();
        let child_key = key();

        // Silent child: keeps every effect.
        let silent = sealed.grant.lattice.clone();
        let child = cert
            .delegate_with_scope_using_key(
                &silent,
                "child".into(),
                sealed.grant.not_after,
                SinkScope::unrestricted(),
                &k,
                &child_key,
            )
            .unwrap();
        let effects =
            effect_surface::granted_effects(&child.effective_permissions().capabilities).unwrap();
        assert_eq!(effects.len(), 2);

        // Greedy child: asks for an effect the grant never had.
        let mut greedy = sealed.grant.lattice.clone();
        effect_surface::grant_effect(&mut greedy.capabilities, "git/push-branch");
        effect_surface::grant_effect(&mut greedy.capabilities, "shell/run-tests");
        let child = cert
            .delegate_with_scope_using_key(
                &greedy,
                "child".into(),
                sealed.grant.not_after,
                SinkScope::unrestricted(),
                &k,
                &child_key,
            )
            .unwrap();
        let effects =
            effect_surface::granted_effects(&child.effective_permissions().capabilities).unwrap();
        assert_eq!(effects.into_iter().collect::<Vec<_>>(), ["shell/run-tests"]);

        // A child that names only an effect the grant lacks, with the marker
        // at `Never`, would come out of the meet with no effect dimension at
        // all: refused rather than read as unconstrained. (A request with
        // the marker at `Never` and nothing else inherits the parent's set,
        // as the tool surface does: it cannot exceed the parent either way.)
        let mut shed = sealed.grant.lattice.clone();
        effect_surface::grant_effect(&mut shed.capabilities, "git/push-branch");
        shed.capabilities.extensions.insert(
            ExtensionOperation::new(effect_surface::EFFECT_SURFACE_MARKER),
            CapabilityLevel::Never,
        );
        let err = cert
            .delegate_with_scope_using_key(
                &shed,
                "child".into(),
                sealed.grant.not_after,
                SinkScope::unrestricted(),
                &k,
                &child_key,
            )
            .unwrap_err();
        assert!(
            matches!(err, crate::CertificateDelegationError::EffectSurfaceDropped),
            "{err}"
        );
    }
}
