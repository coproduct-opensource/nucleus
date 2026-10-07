//! PyO3 bindings for `nucleus_envelope::verify_bundle`.
//!
//! Mirrors the JS SDK semantics:
//!
//! ```python
//! from nucleus_verifier import verify_bundle
//!
//! report = verify_bundle(bundle_json, trust_anchor_json)
//! assert report["ok"] is True
//! assert report["trust_domain"] == "prod.example.com"
//! ```
//!
//! What this SDK does NOT do:
//!
//! - Produce bundles. Signing keys + entropy stay server-side by
//!   design. Use `nucleus-control-plane-server`.
//! - Fetch JWKS over the network. The caller obtains the trust anchor
//!   out of band and passes it as JSON.
//! - Cache results. The caller decides retention.

use nucleus_envelope::{verify_bundle as envelope_verify_bundle, Bundle, TrustAnchor};
use nucleus_lineage::Jwks;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use serde::Deserialize;

/// Wire shape mirroring the JS SDK's `TrustAnchorInput` so the same
/// JSON works for both surfaces.
#[derive(Debug, Deserialize)]
struct TrustAnchorInput {
    #[serde(default)]
    trust_jwks: Option<Jwks>,
    #[serde(default)]
    allow_empty: bool,
    #[serde(default)]
    trust_witness_pubkey_hex: Option<String>,
    #[serde(default)]
    trusted_witnesses_hex: Vec<String>,
    #[serde(default)]
    cosignature_threshold: usize,
    #[serde(default)]
    require_payload_binding: bool,
}

/// Build a `TrustAnchor` from caller-supplied JSON. Decoupled from
/// the PyO3-layer so it can be unit-tested in plain Rust.
fn build_anchor(input: TrustAnchorInput) -> Result<TrustAnchor, String> {
    let mut anchor = match input.trust_jwks {
        Some(jwks) => TrustAnchor::from_jwks(jwks),
        None => TrustAnchor::self_check_only(),
    };
    if input.allow_empty {
        anchor = anchor.allow_empty();
    }
    if let Some(hex_str) = input.trust_witness_pubkey_hex {
        let bytes =
            hex::decode(hex_str.trim()).map_err(|e| format!("trust_witness_pubkey_hex: {e}"))?;
        if bytes.len() != 32 {
            return Err(format!(
                "trust_witness_pubkey_hex must decode to 32 bytes, got {}",
                bytes.len()
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        anchor = anchor.with_witness_pubkey(arr);
    }
    for hex_str in &input.trusted_witnesses_hex {
        let bytes =
            hex::decode(hex_str.trim()).map_err(|e| format!("trusted_witnesses_hex entry: {e}"))?;
        if bytes.len() != 32 {
            return Err(format!(
                "trusted_witnesses_hex entries must decode to 32 bytes, got {}",
                bytes.len()
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        anchor = anchor.with_trusted_witness(arr);
    }
    if input.cosignature_threshold > 0 {
        anchor = anchor.cosignature_threshold(input.cosignature_threshold);
    }
    if input.require_payload_binding {
        anchor = anchor.require_payload_binding();
    }
    Ok(anchor)
}

/// Verify a portable nucleus bundle.
///
/// Args:
///     bundle_json (str): `Bundle` serialized as JSON.
///     trust_anchor_json (str): trust anchor configuration as JSON.
///
/// Returns:
///     dict: verification report (see README for shape).
///
/// Raises:
///     ValueError: invalid JSON, malformed hex, or out-of-range field.
///     RuntimeError: verification rejected.
#[pyfunction]
#[pyo3(text_signature = "(bundle_json, trust_anchor_json, /)")]
fn verify_bundle(
    py: Python<'_>,
    bundle_json: &str,
    trust_anchor_json: &str,
) -> PyResult<Py<PyDict>> {
    let bundle: Bundle = serde_json::from_str(bundle_json)
        .map_err(|e| PyValueError::new_err(format!("bundle JSON: {e}")))?;
    let input: TrustAnchorInput = serde_json::from_str(trust_anchor_json)
        .map_err(|e| PyValueError::new_err(format!("trust anchor JSON: {e}")))?;
    let anchor = build_anchor(input).map_err(PyValueError::new_err)?;
    let report = envelope_verify_bundle(&bundle, &anchor)
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

    let trust_mode = if report.trust_mode_self_check_only {
        "self_check_only"
    } else {
        "out_of_band"
    };

    let dict = PyDict::new(py);
    dict.set_item("ok", true)?;
    dict.set_item("trust_mode", trust_mode)?;
    dict.set_item("trust_domain", report.trust_domain.clone())?;
    dict.set_item("edge_count", report.edge_count)?;
    dict.set_item("checkpoint_count", report.checkpoint_count)?;
    dict.set_item("head_edge_hash_hex", report.head_edge_hash_hex.clone())?;
    dict.set_item("schema_version", bundle.envelope.meta.schema_version)?;
    let kids = PyList::new(py, report.kids.iter().map(String::as_str))?;
    dict.set_item("kids", kids)?;
    dict.set_item("merkle_verified", report.merkle_verified)?;
    dict.set_item("cosignatures_verified", report.cosignatures_verified)?;
    let witnesses = PyList::new(
        py,
        report
            .matched_witness_pubkeys_hex
            .iter()
            .map(String::as_str),
    )?;
    dict.set_item("matched_witness_pubkeys_hex", witnesses)?;
    dict.set_item("payload_binding_verified", report.payload_binding_verified)?;
    Ok(dict.into())
}

/// Envelope schema version this SDK build supports.
#[pyfunction]
fn supported_envelope_schema_version() -> u32 {
    nucleus_envelope::bundle::ENVELOPE_SCHEMA_VERSION
}

/// SDK semver, for diagnostics.
#[pyfunction]
fn sdk_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Core (natively testable) of [`verify_receipt`]. The JSON shape is the JS
/// SDK's `verifyReceipt` verdict, field for field, so one live receipt can be
/// checked for agreement across Rust, JS and Python.
///
/// A copy of `sdks/verifier-js`'s `receipt_verdict` rather than a shared
/// function: the shared home would be `nucleus-receipt`, and changing that
/// crate moves the wasm digest `nucleus-verifier-service` pins.
fn receipt_report(receipt_json: &str, verifying_key_hex: &str) -> Result<String, String> {
    let receipt: nucleus_receipt::Receipt =
        serde_json::from_str(receipt_json).map_err(|e| format!("receipt JSON: {e}"))?;
    let bytes = hex::decode(verifying_key_hex.trim().trim_start_matches("0x"))
        .map_err(|e| format!("verifying_key_hex: {e}"))?;
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|b: Vec<u8>| format!("verifying key must be 32 bytes, got {}", b.len()))?;
    let verdict = match receipt.verify(&key) {
        Ok(()) => serde_json::json!({
            "outcome": "verified",
            "version": receipt.version,
            "session_id": receipt.session.session_id,
            "issuer_kid": receipt.session.issuer_kid,
            "projection_kinds": receipt.projections.iter().map(|p| p.kind()).collect::<Vec<_>>(),
            "root_hash_hex": receipt.root_hash_hex,
        }),
        Err(nucleus_receipt::ReceiptError::RootHashMismatch { expected, actual }) => {
            serde_json::json!({"outcome": "root_hash_mismatch", "expected": expected, "actual": actual})
        }
        Err(nucleus_receipt::ReceiptError::SignatureMismatch(reason)) => {
            serde_json::json!({"outcome": "signature_mismatch", "reason": reason})
        }
        // A structurally unusable key or signature encoding is an input error.
        Err(other) => return Err(other.to_string()),
    };
    serde_json::to_string(&verdict).map_err(|e| e.to_string())
}

/// Verify a colimit receipt (`nucleus-receipt`: Session + Projection[] signed
/// Ed25519 over BLAKE3 of the RFC 8785 canonical bytes) against the issuer's
/// 32-byte verifying key, given as hex. Runs the same `Receipt::verify` as
/// `nucleus-audit` and the JS SDK's `verifyReceipt`.
///
/// Returns the verdict as JSON text: `{"outcome": "verified", "version",
/// "session_id", "issuer_kid", "projection_kinds", "root_hash_hex"}`,
/// `{"outcome": "root_hash_mismatch", "expected", "actual"}` (content changed
/// after signing) or `{"outcome": "signature_mismatch", "reason"}` (wrong key
/// or forged signature). A cryptographic rejection is a value, not an error.
///
/// Raises:
///     ValueError: the receipt does not parse, or the key is not 32 bytes of hex.
#[pyfunction]
#[pyo3(text_signature = "(receipt_json, verifying_key_hex, /)")]
fn verify_receipt(receipt_json: &str, verifying_key_hex: &str) -> PyResult<String> {
    receipt_report(receipt_json, verifying_key_hex).map_err(PyValueError::new_err)
}

/// Core (natively testable) of [`verify_node_evidence`].
fn node_evidence_report(
    evidence: &[u8],
    reference_json: &str,
    relying_party_json: &str,
) -> Result<String, String> {
    let report = nucleus_node_evidence::report(
        evidence,
        reference_json.as_bytes(),
        relying_party_json.as_bytes(),
    )
    .map_err(|e| e.to_string())?;
    serde_json::to_string(&report).map_err(|e| e.to_string())
}

/// Appraise a node's TPM evidence document (ADR 0011) with the same verifier
/// `nucleus-audit verify-node-evidence` and the JS SDK run.
///
/// `evidence` is the document's exact bytes (its SHA-256 is what a receipt's
/// `node_platform.evidence_sha256` names). `relying_party_json` carries the
/// caller's own inputs: `{binding, freshness, trust_roots, operator_pins,
/// now}`, every field required.
///
/// Returns the report as JSON text: `{"outcome": "appraised",
/// "evidence_sha256", "ear"}` (`ear["submods"]["node"]["ear.status"]` is
/// `"affirming"` only for Attested) or `{"outcome": "refused",
/// "evidence_sha256", "refusal"}`.
///
/// Raises:
///     ValueError: a document does not parse.
#[pyfunction]
#[pyo3(text_signature = "(evidence, reference_json, relying_party_json, /)")]
fn verify_node_evidence(
    evidence: &[u8],
    reference_json: &str,
    relying_party_json: &str,
) -> PyResult<String> {
    node_evidence_report(evidence, reference_json, relying_party_json)
        .map_err(PyValueError::new_err)
}

#[pymodule]
fn nucleus_verifier(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(verify_bundle, m)?)?;
    m.add_function(wrap_pyfunction!(verify_node_evidence, m)?)?;
    m.add_function(wrap_pyfunction!(verify_receipt, m)?)?;
    m.add_function(wrap_pyfunction!(verify_payout, m)?)?;
    m.add_function(wrap_pyfunction!(verify_signed_payout, m)?)?;
    m.add_function(wrap_pyfunction!(verify_settlement_set, m)?)?;
    m.add_function(wrap_pyfunction!(verify_mandate_covers_cart, m)?)?;
    m.add_function(wrap_pyfunction!(supported_envelope_schema_version, m)?)?;
    m.add_function(wrap_pyfunction!(sdk_version, m)?)?;
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// COMMERCE: a payee checks its own share, in Python, offline
// ═══════════════════════════════════════════════════════════════════════════
//
// The JS SDK has carried these since the commerce slices landed; Python could
// only verify bundles. "Any runtime, any language" is not true while a payee
// running Python cannot check the split it was paid.
//
// Each binding is a thin wrapper over a NATIVE-TESTABLE core fn, the same shape
// `sdks/verifier-js` uses, so the logic is exercised by `cargo test` rather than
// only through an interpreter.

/// Core of [`verify_payout`]: does this split re-derive from the proven kernels?
fn payout_verdict(payout_json: &str) -> Result<(bool, String), String> {
    use nucleus_recompute::payout::{verify_payout as vp, PayoutClaim};
    use nucleus_recompute::RecomputeOutcome;

    let payout: PayoutClaim =
        serde_json::from_str(payout_json).map_err(|e| format!("payout JSON: {e}"))?;
    Ok(match vp(&payout) {
        RecomputeOutcome::Match => (true, "verified".to_string()),
        RecomputeOutcome::Mismatch { field, .. } => (false, format!("mismatch:{field}")),
        RecomputeOutcome::Invalid(m) => (false, format!("invalid:{m}")),
    })
}

/// Core of [`verify_signed_payout`]: signature first, then recompute.
fn signed_payout_verdict(
    receipt_json: &str,
    verifying_key_hex: &str,
) -> Result<(bool, String), String> {
    use nucleus_recompute::payout::envelope::{verify_signed_payout as vsp, SignedPayoutVerdict};
    use nucleus_recompute::RecomputeOutcome;

    let receipt: nucleus_receipt::Receipt =
        serde_json::from_str(receipt_json).map_err(|e| format!("receipt JSON: {e}"))?;
    let bytes = hex::decode(verifying_key_hex.trim().trim_start_matches("0x"))
        .map_err(|e| format!("verifying_key_hex: {e}"))?;
    let vk: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "verifying key must be 32 bytes".to_string())?;

    Ok(match vsp(&receipt, &vk) {
        SignedPayoutVerdict::Recomputed(RecomputeOutcome::Match) => (true, "verified".into()),
        SignedPayoutVerdict::Recomputed(RecomputeOutcome::Mismatch { field, .. }) => {
            (false, format!("mismatch:{field}"))
        }
        SignedPayoutVerdict::Recomputed(RecomputeOutcome::Invalid(m)) => {
            (false, format!("invalid:{m}"))
        }
        SignedPayoutVerdict::BadSignature => (false, "bad_signature".into()),
        SignedPayoutVerdict::Malformed(e) => (false, format!("malformed:{e}")),
    })
}

/// Core of [`verify_settlement_set`]: was **everyone** paid, exactly once?
fn settlement_set_verdict(
    payout_json: &str,
    attestations_json: &str,
) -> Result<(bool, String), String> {
    use nucleus_recompute::payout::PayoutClaim;
    use nucleus_recompute::settlement_attestation::{
        verify_settlement_set as vss, SettlementAttestation, SettlementSetOutcome,
    };

    let payout: PayoutClaim =
        serde_json::from_str(payout_json).map_err(|e| format!("payout JSON: {e}"))?;
    let attestations: Vec<SettlementAttestation> =
        serde_json::from_str(attestations_json).map_err(|e| format!("attestations JSON: {e}"))?;

    Ok(match vss(&attestations, &payout) {
        SettlementSetOutcome::Complete => (true, "complete".to_string()),
        other => (false, format!("{other:?}")),
    })
}

/// Core of [`verify_mandate_covers_cart`]: did a human approve *this* cart?
fn cart_verdict(mandate_manifest_hash: &str, cart_json: &str) -> Result<(bool, String), String> {
    use nucleus_recompute::cart::{verify_mandate_covers_cart as vmc, Cart, CartOutcome};

    let cart: Cart = serde_json::from_str(cart_json).map_err(|e| format!("cart JSON: {e}"))?;
    Ok(match vmc(mandate_manifest_hash, &cart) {
        CartOutcome::Match => (true, "authorized".to_string()),
        other => (false, format!("{other:?}")),
    })
}

fn verdict_dict(py: Python<'_>, key: &str, ok: bool, verdict: String) -> PyResult<Py<PyDict>> {
    let d = PyDict::new(py);
    d.set_item(key, ok)?;
    d.set_item("verdict", verdict)?;
    Ok(d.into())
}

/// Re-derive a payout's split from its declared inputs via the proven kernels.
///
/// Returns `{"verified": bool, "verdict": str}`. A payout whose underlying
/// clearing does not itself re-derive fails on the *clearing*, before the split
/// is examined — a payout over a fabricated price is caught first.
#[pyfunction]
#[pyo3(text_signature = "(payout_json, /)")]
fn verify_payout(py: Python<'_>, payout_json: &str) -> PyResult<Py<PyDict>> {
    let (ok, v) = payout_verdict(payout_json).map_err(PyValueError::new_err)?;
    verdict_dict(py, "verified", ok, v)
}

/// Verify a SIGNED payout: the Ed25519 signature, then a recompute of the split.
///
/// This is the one that makes a revenue share trustless from Python. A payee
/// pastes what it was sent and recomputes its own share — no server, no operator
/// ledger to trust. An operator that signs a skimmed split still returns
/// `mismatch:allocations`, which a signature-only check cannot catch.
#[pyfunction]
#[pyo3(text_signature = "(receipt_json, verifying_key_hex, /)")]
fn verify_signed_payout(
    py: Python<'_>,
    receipt_json: &str,
    verifying_key_hex: &str,
) -> PyResult<Py<PyDict>> {
    let (ok, v) =
        signed_payout_verdict(receipt_json, verifying_key_hex).map_err(PyValueError::new_err)?;
    verdict_dict(py, "verified", ok, v)
}

/// Was every allocation discharged, exactly once?
///
/// The question a per-receipt check cannot answer: an operator can pay two of
/// three payees and show each of them a receipt that verifies on its own.
#[pyfunction]
#[pyo3(text_signature = "(payout_json, attestations_json, /)")]
fn verify_settlement_set(
    py: Python<'_>,
    payout_json: &str,
    attestations_json: &str,
) -> PyResult<Py<PyDict>> {
    let (ok, v) =
        settlement_set_verdict(payout_json, attestations_json).map_err(PyValueError::new_err)?;
    verdict_dict(py, "complete", ok, v)
}

/// Does a mandate authorize this exact cart?
///
/// `mandate_manifest_hash` must come from a bundle whose signature has ALREADY
/// been verified — this checks coverage, not authenticity, and cannot tell a
/// real mandate from a string.
#[pyfunction]
#[pyo3(text_signature = "(mandate_manifest_hash, cart_json, /)")]
fn verify_mandate_covers_cart(
    py: Python<'_>,
    mandate_manifest_hash: &str,
    cart_json: &str,
) -> PyResult<Py<PyDict>> {
    let (ok, v) = cart_verdict(mandate_manifest_hash, cart_json).map_err(PyValueError::new_err)?;
    verdict_dict(py, "authorized", ok, v)
}

#[cfg(test)]
mod commerce_tests {
    use super::*;

    /// **The test that makes "any runtime, any language" checkable.**
    ///
    /// The conformance corpus is the artifact a third-party runtime consumes to
    /// prove it agrees with nucleus. This runs those exact vectors through the
    /// Python surface's cores — so the Python SDK is held to the same standard
    /// an outside integrator would be, rather than to hand-written cases chosen
    /// by the person who wrote the bindings.
    ///
    /// Only the properties this SDK exposes are covered; `disclosure_required`
    /// is an IFC decision with no Python binding yet, and is skipped explicitly
    /// rather than silently.
    #[test]
    fn the_python_surface_agrees_with_the_conformance_corpus() {
        use nucleus_commerce_conformance::{corpus, CaseInput, Expect, Property};

        let mut checked = 0;
        let mut wrong = Vec::new();
        let mut skipped = Vec::new();

        for case in corpus() {
            let got = match &case.input {
                CaseInput::Payout(p) => {
                    let json = serde_json::to_string(p).unwrap();
                    payout_verdict(&json).map(|(ok, _)| ok)
                }
                CaseInput::Settlement {
                    payout,
                    attestations,
                } => {
                    let pj = serde_json::to_string(payout).unwrap();
                    let aj = serde_json::to_string(attestations).unwrap();
                    settlement_set_verdict(&pj, &aj).map(|(ok, _)| ok)
                }
                CaseInput::Cart {
                    mandate_manifest_hash,
                    cart,
                } => {
                    let cj = serde_json::to_string(cart).unwrap();
                    cart_verdict(mandate_manifest_hash, &cj).map(|(ok, _)| ok)
                }
                CaseInput::Flow(_) => {
                    skipped.push(case.name);
                    continue;
                }
            }
            .expect("the corpus's own inputs must parse");

            checked += 1;
            let want = matches!(case.expect, Expect::Accept);
            if got != want {
                wrong.push(format!(
                    "  {} ({}): expected {:?}, python said {}",
                    case.name, case.summary, case.expect, got
                ));
            }
        }

        assert!(
            wrong.is_empty(),
            "the Python surface disagrees with the corpus:\n{}",
            wrong.join("\n")
        );
        assert!(
            checked >= 10,
            "only {checked} vectors exercised — too few to mean anything"
        );
        assert!(
            skipped.iter().all(|n| n.starts_with("disclosure/")),
            "only the disclosure property may be skipped, got {skipped:?}"
        );
        // And the skip is bounded: every OTHER property must be exercised.
        for p in [
            Property::PayoutRecomputes,
            Property::SettlementDischarges,
            Property::MandateCoversCart,
        ] {
            assert!(
                corpus().iter().any(|c| c.property == p),
                "{p:?} must be exercised through Python"
            );
        }
    }

    /// A signature-valid but skimmed payout is rejected from Python too — the
    /// case a signature-only check cannot catch.
    #[test]
    fn a_validly_signed_but_skimmed_payout_is_rejected_from_python() {
        use ed25519_dalek::SigningKey;
        use nucleus_econ_kernels::commons::CommonsShare;
        use nucleus_receipt::{Receipt, Session};
        use nucleus_recompute::issue_settlement;
        use nucleus_recompute::payout::{
            envelope::to_payout_projection, issue_payout, Attribution,
        };

        let sk = SigningKey::from_bytes(&[21u8; 32]);
        let vk_hex = hex::encode(sk.verifying_key().to_bytes());
        let shares = vec![
            CommonsShare {
                destination: "runtime".into(),
                bps: 3_000,
            },
            CommonsShare {
                destination: "seller".into(),
                bps: 7_000,
            },
        ];
        let attribution = Attribution {
            workload_spiffe_id: "spiffe://test/runtime".into(),
            assurance: 1,
            offer_hash_hex: "a".repeat(64),
            disclosure_hash_hex: String::new(),
        };
        let session = || Session {
            session_id: "spiffe://test/py".into(),
            issuer_kid: "kid".into(),
            issued_at_micros: 1_717_000_000_000_000,
            parent_chain: vec![],
        };

        let honest = issue_payout(
            issue_settlement(1_000_000, 10_000),
            shares.clone(),
            attribution.clone(),
        )
        .expect("well-formed");
        let signed = Receipt::sign(session(), vec![to_payout_projection(&honest)], &sk);
        let (ok, verdict) =
            signed_payout_verdict(&serde_json::to_string(&signed).unwrap(), &vk_hex).unwrap();
        assert!(ok, "honest payout must verify, got {verdict}");

        let mut skimmed =
            issue_payout(issue_settlement(1_000_000, 10_000), shares, attribution).expect("ok");
        skimmed.allocations[0].amount_micro += 1;
        skimmed.allocations[1].amount_micro -= 1;
        let signed = Receipt::sign(session(), vec![to_payout_projection(&skimmed)], &sk);
        let (ok, verdict) =
            signed_payout_verdict(&serde_json::to_string(&signed).unwrap(), &vk_hex).unwrap();
        assert!(!ok, "a skimmed payout must be rejected");
        assert_eq!(verdict, "mismatch:allocations");
    }

    /// Malformed input is a caller error, not a silent pass.
    #[test]
    fn malformed_json_errors_rather_than_verifying() {
        assert!(payout_verdict("{not json").is_err());
        assert!(cart_verdict("abc", "{not json").is_err());
        assert!(signed_payout_verdict("{}", "zz").is_err());
    }
}

/// The Python surface against the Rust verifier's golden reports over the
/// real-TPM fixtures (`crates/nucleus-node-evidence/tests/fixtures/parity/`),
/// the same cases the JS SDK runs through its wasm build.
#[cfg(test)]
mod node_evidence_tests {
    use super::node_evidence_report;

    const FIXTURES: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../crates/nucleus-node-evidence/tests/fixtures"
    );

    fn read(name: &str) -> String {
        std::fs::read_to_string(format!("{FIXTURES}/{name}")).unwrap()
    }

    #[test]
    fn every_parity_case_reproduces_the_rust_verifiers_golden_report() {
        let cases: serde_json::Value = serde_json::from_str(&read("parity/cases.json")).unwrap();
        let cases = cases["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 7);
        for case in cases {
            let got = node_evidence_report(
                read(case["evidence"].as_str().unwrap()).as_bytes(),
                &read(case["reference"].as_str().unwrap()),
                &case["relying_party"].to_string(),
            )
            .unwrap();
            let got: serde_json::Value = serde_json::from_str(&got).unwrap();
            let want: serde_json::Value =
                serde_json::from_str(&read(case["report"].as_str().unwrap())).unwrap();
            assert_eq!(got, want, "{}", case["name"]);
        }
    }

    #[test]
    fn an_unreadable_relying_party_document_is_an_error_not_a_verdict() {
        let err = node_evidence_report(
            read("live-node-epoch4-evidence.json").as_bytes(),
            &read("live-node-reference-exact.json"),
            "{}",
        )
        .unwrap_err();
        assert!(err.starts_with("relying party:"), "{err}");
    }
}

#[cfg(test)]
mod receipt_tests {
    use super::receipt_report;
    use ed25519_dalek::SigningKey;
    use nucleus_receipt::{Projection, Receipt, Session};

    fn signed(key: &SigningKey) -> Receipt {
        Receipt::sign(
            Session {
                session_id: "pod-1".into(),
                issuer_kid: "node".into(),
                issued_at_micros: 7,
                parent_chain: Vec::new(),
            },
            vec![Projection::Ci(serde_json::json!({"exit_code": 0}))],
            key,
        )
    }

    fn outcome(receipt: &Receipt, key: &SigningKey) -> serde_json::Value {
        let report = receipt_report(
            &serde_json::to_string(receipt).unwrap(),
            &hex::encode(key.verifying_key().to_bytes()),
        )
        .unwrap();
        serde_json::from_str(&report).unwrap()
    }

    #[test]
    fn a_signed_receipt_verifies_and_a_changed_one_is_a_root_hash_mismatch() {
        let key = SigningKey::from_bytes(&[3; 32]);
        let receipt = signed(&key);
        let ok = outcome(&receipt, &key);
        assert_eq!(ok["outcome"], "verified");
        assert_eq!(ok["session_id"], "pod-1");
        assert_eq!(ok["projection_kinds"], serde_json::json!(["ci"]));
        assert_eq!(ok["root_hash_hex"], receipt.root_hash_hex.as_str());
        let mut changed = receipt.clone();
        changed.session.issued_at_micros += 1;
        assert_eq!(outcome(&changed, &key)["outcome"], "root_hash_mismatch");
        let other = SigningKey::from_bytes(&[4; 32]);
        assert_eq!(outcome(&receipt, &other)["outcome"], "signature_mismatch");
    }

    #[test]
    fn malformed_input_is_an_error_not_a_verdict() {
        assert!(receipt_report("{}", &"00".repeat(32)).is_err());
        let key = SigningKey::from_bytes(&[3; 32]);
        let receipt = serde_json::to_string(&signed(&key)).unwrap();
        assert!(receipt_report(&receipt, "00").is_err());
        assert!(receipt_report(&receipt, "zz").is_err());
    }
}
