//! Assurance rung — *how much trust* an externality claim's `units_micro`
//! demands, as a single machine-readable ordinal.
//!
//! The Pigouvian charge is `λ · units_micro / 1e6`. We publish + unit-test `λ`
//! (verifiable). `units_micro` is the *attested consumption* — exactly as honest
//! as the oracle behind it. This module turns "how honest is it?" from a footnote
//! into a checkable field: the **assurance rung**.
//!
//! ## Derived, not asserted
//!
//! The rung is **derived from what actually verified**, never self-asserted by
//! the claimant. [`assess_rung`] takes the boolean outcomes of the independent
//! verification layers (signature, TEE attestation, multi-source dispute, zk
//! upper-envelope — see [`crate::oracle`]) and returns the highest rung whose
//! property holds. So a claim cannot *lie* about its rung: a higher rung requires
//! the corresponding verification to actually pass.
//!
//! ## A profile is only as honest as its weakest claim
//!
//! An [`crate::ExternalityProfile`] bundles one claim per dimension; its overall
//! assurance is the **minimum** rung across its claims
//! ([`crate::ExternalityProfile::min_assurance_rung`]) — the weakest link, the
//! number a consumer of the receipt should actually trust.
//!
//! See `docs/rfcs/externality-oracle.md` for the full trust-residue ladder and
//! the irreducible rung-5 residue (the physical sensor) that no rung removes.

use serde::{Deserialize, Serialize};

/// The achieved assurance rung for an externality claim — smaller rung = larger
/// trusted surface. Ordered: `SelfReported < OracleSigned < TeeAttested <
/// MultiSourceDisputed < ZkUpperEnvelope`.
///
/// **Derive this with [`assess_rung`]; do not let a claimant set it directly.**
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssuranceRung {
    /// **R0** — self-reported, no independent verification. The greenwashing
    /// baseline; the trusted surface is the claimant itself. We never emit this
    /// for a *verified* claim — it is the floor a failed verification falls to.
    ///
    /// [`assess_rung`] cannot return it, because that function requires a
    /// [`crate::SignatureVerified`] to be called at all. A caller reporting a
    /// failed verification names this variant directly, which is honest: it is
    /// a label, not evidence.
    SelfReported,
    /// **R1** — an independent oracle's Ed25519 signature verified (fresh, bound
    /// to the subject identity + resource tag). The floor for any verified
    /// [`crate::SignedExternalityClaim`]. Trusted surface: the oracle operator.
    OracleSigned,
    /// **R2** — additionally TEE-attested: the units came out of an attested
    /// enclave running known code ([`crate::TeeAttestation`]). The operator can
    /// no longer silently alter the number — only feed a bad input.
    TeeAttested,
    /// **R3** — additionally corroborated by multiple independent sources under a
    /// staked optimistic-oracle dispute window (the UMA pattern; reuse the Bet B
    /// bond/challenge machinery). Trusted surface: a majority of feeds + no
    /// profitable undisputed lie. Not derivable from a single claim in isolation
    /// — the aggregation layer supplies the `multi_source_disputed` flag.
    MultiSourceDisputed,
    /// **R4** — additionally bounded above by a verified zk upper-envelope proof
    /// ([`crate::UpperEnvelopeProof`]): over-claiming is impossible without
    /// detection. Trusted surface: the public model + its public inputs.
    ZkUpperEnvelope,
}

impl AssuranceRung {
    /// The ordinal level (0..=4). Higher = smaller trusted surface.
    pub fn level(self) -> u8 {
        match self {
            AssuranceRung::SelfReported => 0,
            AssuranceRung::OracleSigned => 1,
            AssuranceRung::TeeAttested => 2,
            AssuranceRung::MultiSourceDisputed => 3,
            AssuranceRung::ZkUpperEnvelope => 4,
        }
    }

    /// A short stable label for receipts / dashboards (matches the serde tag).
    pub fn label(self) -> &'static str {
        match self {
            AssuranceRung::SelfReported => "self_reported",
            AssuranceRung::OracleSigned => "oracle_signed",
            AssuranceRung::TeeAttested => "tee_attested",
            AssuranceRung::MultiSourceDisputed => "multi_source_disputed",
            AssuranceRung::ZkUpperEnvelope => "zk_upper_envelope",
        }
    }
}

/// Derive the achieved [`AssuranceRung`] from WITNESSES that each layer
/// verified — never from booleans a caller can type.
///
/// # Why witnesses and not `bool`
///
/// This function used to take four `bool`s. Measured on 2026-09-21 against the
/// then-current tree: a claim carrying a ONE-BYTE TEE quote and a one-byte
/// "proof" whose self-declared `public_inputs[0]` was `u64::MAX` reached
/// `ZkUpperEnvelope`, the top rung. Nothing lied — the two stub verifiers
/// checked well-formedness, reported success, and this function was handed
/// `true, true`. The rung was derived exactly as documented, from inputs that
/// meant "well-formed" rather than "verified".
///
/// So each argument is now evidence with a private constructor, minted only by
/// the checker for that layer (ADR 0007 C-1, C-2). `assess_rung(true, true,
/// false, true)` no longer compiles, and a shape check cannot be passed where
/// an attestation is wanted because
/// [`crate::QuoteWellFormed`] is a different type from
/// [`crate::TeeAttested`] (C-3: a capability is indexed by what it
/// authorizes).
///
/// Returns the **highest rung whose property holds**. A higher rung never
/// implies a lower one mechanically (TEE+envelope without a dispute is genuine
/// R4), but every rung above R0 requires the signature witness — an unsigned
/// claim is self-reported no matter what else is attached, which is why that
/// one parameter is not optional.
pub fn assess_rung(
    _signature: &crate::SignatureVerified,
    tee: Option<&crate::TeeAttested>,
    disputed: Option<&crate::Disputed>,
    envelope: Option<&crate::EnvelopeBounded>,
) -> AssuranceRung {
    // The signature witness is not optional: holding one IS `signature_ok`,
    // and there is no way to reach this function without it. The old
    // `if !signature_ok { SelfReported }` branch is now unrepresentable, so
    // `SelfReported` is reachable only through `rung_of_unverified_claim`.
    let (tee_ok, multi_source_disputed, zk_envelope_ok) =
        (tee.is_some(), disputed.is_some(), envelope.is_some());
    // Highest satisfied property wins. zk-envelope and multi-source are both
    // strictly stronger than bare TEE; envelope (over-claim-proof) is the
    // strongest single guarantee we can derive today.
    if zk_envelope_ok {
        AssuranceRung::ZkUpperEnvelope
    } else if multi_source_disputed {
        AssuranceRung::MultiSourceDisputed
    } else if tee_ok {
        AssuranceRung::TeeAttested
    } else {
        AssuranceRung::OracleSigned
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_is_monotone_in_level() {
        let ladder = [
            AssuranceRung::SelfReported,
            AssuranceRung::OracleSigned,
            AssuranceRung::TeeAttested,
            AssuranceRung::MultiSourceDisputed,
            AssuranceRung::ZkUpperEnvelope,
        ];
        for w in ladder.windows(2) {
            assert!(w[0] < w[1], "rung order must match trusted-surface size");
            assert!(w[0].level() < w[1].level(), "level must agree with Ord");
        }
    }

    /// "Unsigned" stopped being a parameter value: `assess_rung` cannot be
    /// called without a signature witness, so the floor is named directly and
    /// is the bottom of the ladder.
    #[test]
    fn the_floor_is_the_bottom_of_the_ladder() {
        assert_eq!(AssuranceRung::SelfReported.level(), 0);
        assert!(AssuranceRung::SelfReported < AssuranceRung::OracleSigned);
    }

    #[test]
    fn bare_signature_is_r1() {
        let sig = crate::SignatureVerified::for_test();
        assert_eq!(
            assess_rung(&sig, None, None, None),
            AssuranceRung::OracleSigned
        );
    }

    #[test]
    fn signature_plus_tee_is_r2() {
        let sig = crate::SignatureVerified::for_test();
        let tee = crate::TeeAttested::for_test();
        assert_eq!(
            assess_rung(&sig, Some(&tee), None, None),
            AssuranceRung::TeeAttested
        );
    }

    #[test]
    fn multi_source_outranks_tee() {
        let sig = crate::SignatureVerified::for_test();
        let tee = crate::TeeAttested::for_test();
        let disputed = crate::Disputed::for_test();
        assert_eq!(
            assess_rung(&sig, Some(&tee), Some(&disputed), None),
            AssuranceRung::MultiSourceDisputed
        );
    }

    #[test]
    fn zk_envelope_is_the_top_derivable_rung() {
        // Envelope present → R4 even without a dispute window (genuinely the
        // strongest single guarantee: over-claiming is detectable).
        let sig = crate::SignatureVerified::for_test();
        let tee = crate::TeeAttested::for_test();
        let disputed = crate::Disputed::for_test();
        let env = crate::EnvelopeBounded::for_test();
        assert_eq!(
            assess_rung(&sig, Some(&tee), None, Some(&env)),
            AssuranceRung::ZkUpperEnvelope
        );
        assert_eq!(
            assess_rung(&sig, Some(&tee), Some(&disputed), Some(&env)),
            AssuranceRung::ZkUpperEnvelope
        );
    }

    /// **The repair, as a test.** The top rung needs the envelope WITNESS, and
    /// the only thing a self-declared bound yields is
    /// `EnvelopeSelfDeclared` — a different type. So the rung a forged claim
    /// reached on 2026-09-21 is now reachable only with a real verifier, and
    /// this pair shows the rung genuinely moves with the witness rather than
    /// being constant.
    #[test]
    fn the_top_rung_moves_with_the_envelope_witness() {
        let sig = crate::SignatureVerified::for_test();
        let tee = crate::TeeAttested::for_test();
        let env = crate::EnvelopeBounded::for_test();
        assert_eq!(
            assess_rung(&sig, Some(&tee), None, None),
            AssuranceRung::TeeAttested,
            "without the envelope witness the rung must fall back"
        );
        assert_eq!(
            assess_rung(&sig, Some(&tee), None, Some(&env)),
            AssuranceRung::ZkUpperEnvelope
        );
    }

    #[test]
    fn labels_match_serde_tags() {
        let v = AssuranceRung::ZkUpperEnvelope;
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(json, format!("\"{}\"", v.label()));
        let back: AssuranceRung = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}
