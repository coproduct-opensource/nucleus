//! Proof-carrying admission: the `PostureClaim`.
//!
//! FM-5 proves — in Lean, over the Aeneas-extracted delivery relation — that a
//! workload built the nucleus way never receives identity material. That proof
//! is about an ARTIFACT (a specific guest rootfs). This module lets a pod CARRY
//! the claim "my artifact was proven to enforce posture P" as a label, and lets
//! a node VERIFY it at admission against two things a lying pod cannot control:
//!
//!   1. the rootfs digest the host measures ITSELF (the same hashing
//!      [`nucleus_identity::attestation::LaunchAttestation`] uses), so a pod
//!      cannot claim to be an artifact it is not; and
//!   2. an operator-configured registry of `(posture, digest)` pairs a trusted
//!      builder has proven — so the claim means "a trusted builder proved P for
//!      THIS artifact", not merely "the pod declared its own hash".
//!
//! The check is FAIL-CLOSED: a malformed claim, a digest that does not match the
//! host's measurement, or a `(posture, digest)` the registry does not trust each
//! REFUSE the pod. Absence of a claim is inert — behaviour is unchanged, matching
//! the DLC-D "unprovisioned ⇒ inert" idiom. This is the anti-theater discipline
//! of `AssuranceCoverage.lean`'s reached-vs-unreached obligation made concrete:
//! the claim is checked against a measurement the pod cannot forge, and the
//! outcome is stamped onto the pod record rather than carried and never read.

use std::collections::BTreeSet;

/// The label key a pod uses to carry its posture claim.
pub const POSTURE_LABEL: &str = "dlc_posture";

/// A SHA-256 rootfs digest is 32 bytes = 64 lowercase hex characters.
const DIGEST_HEX_LEN: usize = 64;

fn is_hex_digest(s: &str) -> bool {
    s.len() == DIGEST_HEX_LEN && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// A claim that a named security posture was proven for a specific artifact,
/// identified by its rootfs digest. Parsed from a `dlc_posture` label whose
/// value is `"<posture>@<hex rootfs digest>"`, e.g.
/// `identity_nondelivery@<64 hex chars>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostureClaim {
    /// The posture name, e.g. `identity_nondelivery`. Opaque here; its MEANING
    /// is the FM-5 proof, and the registry is what binds name to that proof.
    pub posture: String,
    /// The claimed artifact digest, lowercase hex.
    pub artifact_digest_hex: String,
}

impl PostureClaim {
    /// Parse the label value.
    ///
    /// - `Ok(None)` — no such label. The pod carries no claim (inert).
    /// - `Ok(Some(_))` — a well-formed claim.
    /// - `Err(_)` — the label is present but malformed. Fail-closed: a malformed
    ///   claim is a REFUSAL, never a silent ignore (a typo must not downgrade a
    ///   pod that meant to be held to the posture).
    pub fn parse(label_value: Option<&str>) -> Result<Option<Self>, String> {
        let raw = match label_value {
            None => return Ok(None),
            Some(s) => s.trim(),
        };
        if raw.is_empty() {
            return Err("dlc_posture label is present but empty".to_string());
        }
        let (posture, digest) = raw.split_once('@').ok_or_else(|| {
            format!("malformed dlc_posture (want `<posture>@<hexdigest>`): {raw}")
        })?;
        let posture = posture.trim();
        let digest = digest.trim().to_ascii_lowercase();
        if posture.is_empty() {
            return Err("dlc_posture has an empty posture name".to_string());
        }
        if !is_hex_digest(&digest) {
            return Err(format!(
                "dlc_posture digest is not {DIGEST_HEX_LEN} hex chars: {digest:?}"
            ));
        }
        Ok(Some(Self {
            posture: posture.to_string(),
            artifact_digest_hex: digest,
        }))
    }

    /// Verify this claim against the digest the HOST measured over the artifact
    /// it is about to boot (`measured_digest_hex`, unforgeable by the pod) and
    /// the operator's trust `registry`. Returns the canonical `"<posture>:verified"`
    /// stamp on success; `Err` (which the caller MUST turn into a refusal) when
    /// either the digest does not match the measurement or no trusted builder has
    /// proven this posture for this artifact.
    pub fn verify_against(
        &self,
        measured_digest_hex: &str,
        registry: &PostureRegistry,
    ) -> Result<String, String> {
        // (1) The pod is not lying about which artifact it is: its claimed digest
        // must equal the digest the host measured itself.
        let measured = measured_digest_hex.trim().to_ascii_lowercase();
        if self.artifact_digest_hex != measured {
            return Err(format!(
                "posture claim digest {} does not match the host-measured rootfs {}",
                self.artifact_digest_hex, measured
            ));
        }
        // (2) A trusted builder proved THIS posture for THIS artifact. An empty
        // registry trusts nothing, so a claim cannot be admitted without a
        // configured anchor — fail-closed. The empty case is called out
        // separately because it is the likely operator misconfiguration (a
        // `dlc_posture` label set without a `NUCLEUS_NODE_TRUSTED_POSTURES` to
        // anchor it), and a clear refusal beats a puzzling one.
        if !registry.trusts(&self.posture, &self.artifact_digest_hex) {
            return Err(if registry.is_empty() {
                format!(
                    "posture claim `{}` for artifact {} refused: the trusted-posture \
                     registry is empty (set NUCLEUS_NODE_TRUSTED_POSTURES to anchor it)",
                    self.posture, self.artifact_digest_hex,
                )
            } else {
                format!(
                    "no trusted builder has proven posture `{}` for artifact {} \
                     (trusted-posture registry has {} entr{})",
                    self.posture,
                    self.artifact_digest_hex,
                    registry.len(),
                    if registry.len() == 1 { "y" } else { "ies" },
                )
            });
        }
        Ok(format!("{}:verified", self.posture))
    }
}

/// The operator-configured set of `(posture, digest)` pairs a trusted builder
/// has proven. Canonical key: `"<posture>@<lowerhex>"`. An EMPTY registry trusts
/// nothing — so a pod carrying a claim is refused when no anchor is configured
/// (fail-closed), while a pod carrying no claim is unaffected.
#[derive(Debug, Clone, Default)]
pub struct PostureRegistry {
    trusted: BTreeSet<String>,
}

impl PostureRegistry {
    /// Parse from a comma-, whitespace-, or newline-separated operator string of
    /// `<posture>@<hexdigest>` entries (the `NUCLEUS_NODE_TRUSTED_POSTURES` env).
    /// Malformed entries are dropped rather than trusted — a garbled entry must
    /// never widen the trust set.
    pub fn from_operator_str(s: &str) -> Self {
        let trusted = s
            .split([',', '\n', '\r', ' ', '\t'])
            .map(str::trim)
            .filter(|e| !e.is_empty())
            .filter_map(|e| {
                let (p, d) = e.split_once('@')?;
                let p = p.trim();
                let d = d.trim().to_ascii_lowercase();
                if p.is_empty() || !is_hex_digest(&d) {
                    return None;
                }
                Some(format!("{p}@{d}"))
            })
            .collect();
        Self { trusted }
    }

    pub fn is_empty(&self) -> bool {
        self.trusted.is_empty()
    }

    pub fn len(&self) -> usize {
        self.trusted.len()
    }

    fn trusts(&self, posture: &str, digest_hex: &str) -> bool {
        self.trusted
            .contains(&format!("{posture}@{}", digest_hex.to_ascii_lowercase()))
    }
}

/// The proof-carrying-admission gate. Kept here with the claim/registry logic
/// (and out of `main.rs`, which is line-ratcheted) so the measure→verify→
/// fail-closed path is one unit, testable end to end against a real on-disk
/// rootfs — not just the pure parse/registry logic above.
///
/// - `Ok(None)` — the pod carried no `dlc_posture` claim (inert; unchanged).
/// - `Ok(Some(stamp))` — a claim was present, its digest matched the rootfs the
///   node measured ITSELF, and a trusted builder has proven that posture for
///   that artifact. `stamp` is `"<posture>:verified"`, to be recorded on the pod.
/// - `Err(_)` — a claim was present and FAILED (malformed, no image to measure,
///   digest mismatch, or untrusted). The caller must refuse the pod; this is the
///   refusal point, before any driver is spawned.
pub(crate) async fn admit_posture(
    spec: &nucleus_spec::PodSpec,
    id: uuid::Uuid,
    registry: &PostureRegistry,
) -> Result<Option<String>, crate::ApiError> {
    use crate::ApiError;
    let claim =
        match PostureClaim::parse(spec.metadata.labels.get(POSTURE_LABEL).map(String::as_str))
            .map_err(ApiError::Driver)?
        {
            None => return Ok(None),
            Some(claim) => claim,
        };
    // A claim names a rootfs digest, so it is only meaningful with an image to
    // measure. Fail-closed if there is nothing to measure.
    let rootfs = spec
        .spec
        .image
        .as_ref()
        .map(|i| i.rootfs_path.clone())
        .ok_or_else(|| {
            ApiError::Driver(
                "pod carries a dlc_posture claim but has no spec.image to measure".to_string(),
            )
        })?;
    let measured = hex::encode(
        nucleus_identity::attestation::measure_artifact(&rootfs)
            .await
            .map_err(|e| {
                ApiError::Driver(format!(
                    "cannot measure rootfs for posture verification: {e}"
                ))
            })?,
    );
    let stamp = claim
        .verify_against(&measured, registry)
        .map_err(ApiError::Driver)?;
    tracing::info!(
        target: "posture",
        pod = %id,
        measured = %measured,
        stamp = %stamp,
        "posture claim verified against host-measured rootfs",
    );
    Ok(Some(stamp))
}

#[cfg(test)]
mod tests {
    use super::*;

    // A valid-looking 64-hex-char digest and a second, distinct one.
    const D1: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const D2: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn registry_of(entries: &[&str]) -> PostureRegistry {
        PostureRegistry::from_operator_str(&entries.join(","))
    }

    #[test]
    fn no_label_is_inert() {
        assert_eq!(PostureClaim::parse(None).unwrap(), None);
    }

    #[test]
    fn present_but_empty_is_refused() {
        assert!(PostureClaim::parse(Some("   ")).is_err());
    }

    #[test]
    fn missing_at_sign_is_refused() {
        assert!(PostureClaim::parse(Some("identity_nondelivery")).is_err());
    }

    #[test]
    fn empty_posture_name_is_refused() {
        assert!(PostureClaim::parse(Some(&format!("@{D1}"))).is_err());
    }

    #[test]
    fn short_or_nonhex_digest_is_refused() {
        assert!(PostureClaim::parse(Some("p@deadbeef")).is_err());
        assert!(PostureClaim::parse(Some(&format!("p@{}", "z".repeat(64)))).is_err());
    }

    #[test]
    fn well_formed_claim_parses_and_lowercases() {
        let c = PostureClaim::parse(Some(&format!("identity_nondelivery@{}", D1.to_uppercase())))
            .unwrap()
            .unwrap();
        assert_eq!(c.posture, "identity_nondelivery");
        assert_eq!(c.artifact_digest_hex, D1); // lowercased
    }

    #[test]
    fn admitted_when_digest_matches_and_trusted() {
        let claim = PostureClaim::parse(Some(&format!("identity_nondelivery@{D1}")))
            .unwrap()
            .unwrap();
        let reg = registry_of(&[&format!("identity_nondelivery@{D1}")]);
        assert_eq!(
            claim.verify_against(D1, &reg).unwrap(),
            "identity_nondelivery:verified"
        );
    }

    #[test]
    fn refused_when_pod_lies_about_its_digest() {
        // Claim says D1, but the host measured D2 — the pod is not the artifact
        // it claims to be. Fail-closed even though (posture, D1) is trusted.
        let claim = PostureClaim::parse(Some(&format!("identity_nondelivery@{D1}")))
            .unwrap()
            .unwrap();
        let reg = registry_of(&[&format!("identity_nondelivery@{D1}")]);
        assert!(claim.verify_against(D2, &reg).is_err());
    }

    #[test]
    fn refused_when_artifact_matches_but_is_untrusted() {
        // Digest matches the measurement, but no trusted builder proved this
        // posture for it — the registry is the difference between "the pod
        // declared its own hash" and "a trusted builder proved this".
        let claim = PostureClaim::parse(Some(&format!("identity_nondelivery@{D1}")))
            .unwrap()
            .unwrap();
        let reg = registry_of(&[&format!("some_other_posture@{D1}")]);
        assert!(claim.verify_against(D1, &reg).is_err());
    }

    #[test]
    fn empty_registry_trusts_nothing() {
        let claim = PostureClaim::parse(Some(&format!("identity_nondelivery@{D1}")))
            .unwrap()
            .unwrap();
        let reg = PostureRegistry::default();
        assert!(reg.is_empty());
        assert!(claim.verify_against(D1, &reg).is_err());
    }

    #[test]
    fn registry_drops_malformed_entries() {
        // A garbled entry must never widen the trust set.
        let reg = registry_of(&["not-an-entry", "p@short", &format!("good@{D1}")]);
        assert_eq!(reg.len(), 1);
        assert!(reg.trusts("good", D1));
        assert!(!reg.trusts("not-an-entry", ""));
    }

    #[test]
    fn registry_parse_is_whitespace_and_comma_tolerant() {
        let reg = PostureRegistry::from_operator_str(&format!(
            "  identity_nondelivery@{D1} ,\n other@{D2}\t"
        ));
        assert_eq!(reg.len(), 2);
        assert!(reg.trusts("identity_nondelivery", D1));
        assert!(reg.trusts("other", D2));
    }
}
