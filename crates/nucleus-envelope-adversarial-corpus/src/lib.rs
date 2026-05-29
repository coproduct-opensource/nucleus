//! Adversarial bundle corpus for `nucleus-envelope`.
//!
//! Every entry returned by [`corpus`] is a bundle constructed to
//! exercise a specific failure mode. `verify_bundle(&case.build(),
//! &case.anchor())` MUST reject — when it doesn't, a regression has
//! crept past the per-edge proof / chain / Merkle / trust-anchor
//! checks.
//!
//! The corpus is wired into CI as a load-bearing gate: a `cargo test
//! -p nucleus-envelope-adversarial-corpus` run on every PR is what
//! turns "we ran an audit" into "an adversary's attacks fail every
//! merge." Referenced by name in
//! [`docs/verifier-service-threat-model.md`](../../../docs/verifier-service-threat-model.md)
//! and [`docs/audit-charter.md`](../../../docs/audit-charter.md).
//!
//! # Adding a new case
//!
//! 1. Write a builder fn returning a `Bundle` (start from
//!    `fixture::known_good_bundle`, mutate, return).
//! 2. Add an [`AdversarialCase`] to [`corpus`] with name + summary +
//!    `expected_kind` discriminant string.
//! 3. Document the attack scenario in the doc-comment above the
//!    builder fn.
//!
//! Existing cases are inspired by the standard CT-log / X.509
//! transparency attack catalogue + the OIDC OP audit's HIGH findings.

use nucleus_envelope::{Bundle, TrustAnchor};
use nucleus_lineage::Jwks;

pub mod cases;
pub mod fixture;

/// One adversarial test vector.
///
/// `expected_kind_substr` is matched (via `contains`) against the
/// `Debug` of the `VerifyBundleError` we expect — stable across
/// patch releases as long as the variant identifier is unchanged.
pub struct AdversarialCase {
    /// Stable identifier (use in audit reports + test failures).
    pub name: &'static str,
    /// Human-readable description of the attack the case exercises.
    pub summary: &'static str,
    /// `Debug`-format substring of the `VerifyBundleError` variant
    /// we expect when `verify_bundle` is called. Allows the corpus
    /// to be robust to error-message rewording while still pinning
    /// the failing variant.
    pub expected_kind_substr: &'static str,
    /// Closure that returns a freshly-constructed bundle + the
    /// trust anchor a defender would use against it. Generators are
    /// `Fn` (not `FnMut`) so the corpus is reusable in parallel.
    pub build: fn() -> (Bundle, TrustAnchor),
}

/// The full corpus. **Adding a case requires extending this Vec.**
///
/// Order matters: cases later in the slice are higher-stakes
/// (impossible-to-recover-from-silent-acceptance failures); cases
/// earlier are bread-and-butter integrity checks. Audit reports
/// should walk the corpus in order so the most catastrophic class
/// of failure is examined last.
pub fn corpus() -> Vec<AdversarialCase> {
    vec![
        AdversarialCase {
            name: "C01_tampered_edge_child",
            summary: "Mutate the child SPIFFE id of an edge mid-chain to point at an \
                      attacker pod; the OutsideRoot check catches the cross-session \
                      contamination before the signature check even runs.",
            expected_kind_substr: "OutsideRoot",
            build: cases::c01_tampered_edge_child,
        },
        AdversarialCase {
            name: "C02_swapped_edge_signatures",
            summary: "Swap the proof signature between two distinct \
                      edges; neither signature covers the recipient \
                      payload, both must fail.",
            expected_kind_substr: "Chain",
            build: cases::c02_swapped_edge_signatures,
        },
        AdversarialCase {
            name: "C03_truncated_envelope",
            summary: "Drop the last edge from a valid envelope. v1 envelopes \
                      accept truncation as a fragmentary truth (real-world risk \
                      documented in audit MED-2); this case demands a payload binding \
                      in the trust anchor, which the truncated bundle lacks.",
            expected_kind_substr: "MissingPayloadBinding",
            build: cases::c03_truncated_envelope,
        },
        AdversarialCase {
            name: "C04_empty_envelope_strict",
            summary: "Bundle with zero edges + strict-allow-empty=false \
                      trust anchor; must reject as a vacuous claim.",
            expected_kind_substr: "EmptyEnvelope",
            build: cases::c04_empty_envelope_strict,
        },
        AdversarialCase {
            name: "C05_attacker_jwks",
            summary: "Bundle's embedded JWKS lists an attacker key; the \
                      verifier must use the out-of-band trust JWKS \
                      instead and reject when signatures don't match it.",
            expected_kind_substr: "Chain",
            build: cases::c05_attacker_jwks,
        },
        AdversarialCase {
            name: "C06_unknown_kid",
            summary: "An edge's proof claims a `kid` not in the \
                      trust anchor's JWKS; must reject for missing key.",
            expected_kind_substr: "Chain",
            build: cases::c06_unknown_kid,
        },
        AdversarialCase {
            name: "C07_foreign_parent",
            summary: "Edge parent points to a SPIFFE id outside the \
                      session root; must reject as cross-session contamination.",
            expected_kind_substr: "OutsideRoot",
            build: cases::c07_foreign_parent,
        },
        AdversarialCase {
            name: "C08_session_root_not_pod",
            summary: "Bundle's session_root carries a `/call/` suffix \
                      (a call id, not a pod root); must reject as malformed.",
            expected_kind_substr: "SessionRootNotPod",
            build: cases::c08_session_root_not_pod,
        },
    ]
}

/// Convenience for callers that want a single deterministic
/// trust anchor + JWKS pair across all cases (audit reports often
/// embed the JWKS hex). Wraps [`fixture::known_good_issuer_jwks`].
pub fn shared_jwks() -> Jwks {
    fixture::known_good_issuer_jwks()
}

#[cfg(test)]
mod doc_tests {
    use super::*;

    #[test]
    fn corpus_is_non_empty() {
        assert!(
            !corpus().is_empty(),
            "the corpus must contain at least one case"
        );
    }

    #[test]
    fn case_names_are_unique() {
        let names: Vec<&str> = corpus().iter().map(|c| c.name).collect();
        let mut sorted = names.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            names.len(),
            sorted.len(),
            "every case name must be unique; got {names:?}"
        );
    }

    #[test]
    fn case_names_follow_convention() {
        // Every case is `CNN_snake_case_description` — easy to grep,
        // sortable, stable across renames within a series.
        for case in corpus() {
            let prefix = &case.name[..3];
            assert!(
                prefix.starts_with('C') && prefix[1..].chars().all(|c| c.is_ascii_digit()),
                "case name must start with C<NN>: got {:?}",
                case.name
            );
        }
    }
}
