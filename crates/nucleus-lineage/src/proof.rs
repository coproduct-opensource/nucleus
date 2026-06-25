//! Cryptographic proof carried alongside [`LineageEdge`] records.
//!
//! This module ships the **wire format** for proofs and the **canonical-bytes
//! computation** that proofs are signed over. Actual signing/verification
//! happens in the issuer impl (e.g. [`LocalIssuer`](crate::local_issuer)) and
//! in a future verifier — those land in PR-D.
//!
//! Today, [`LineageEdge::proof`] is `None` for every edge produced by this
//! crate (legacy/unsigned). This module exists so the wire format has a slot
//! for the cryptographic evidence — adding signing later does not require a
//! breaking change to the JSONL log format.
//!
//! # Canonical encoding
//!
//! [`canonical_edge_bytes`] returns the bytes a signer should sign and a
//! verifier should verify against. The encoding is deterministic:
//!
//! 1. `child` SPIFFE ID, NUL-separated
//! 2. `kind` discriminator (snake_case), NUL-separated
//! 3. parent SPIFFE IDs in given order, each NUL-separated
//! 4. content hash (32 zero bytes if absent)
//! 5. RFC3339 timestamp string, NUL-separated
//! 6. previous edge's content hash from the proof chain (32 zero bytes if absent)
//! 7. verifier-attestation block, **emitted only when
//!    `edge.verifier_attestation` is `Some`**: a single NUL delimiter
//!    followed by 6 NUL-terminated fields in this order —
//!    `verifier_binary_hash`, `wasmtime_version`, `wasmtime_config_hash`,
//!    `vrf_params_hash`, `external_snapshot_root`, `lean_spec_hash`. Absent
//!    sub-fields emit the empty string (just their NUL terminator).
//!
//! **Additive-compatibility invariant.** When `verifier_attestation` is
//! `None` (every pre-existing edge kind: `PodAdmit` / `ToolCall` /
//! `LlmCall` / `ArtifactProduced` / `Merge` / `DocumentRetrieved` /
//! `Other`), step 7 contributes NOTHING — the canonical bytes are
//! byte-identical to the pre-attestation encoding. This is a deliberate
//! divergence from the platform fork (which always appends a 7-byte VA
//! footer): emitting the footer unconditionally would change the signed
//! bytes of every legacy edge. Gating on `Some` keeps the merge purely
//! additive while still binding the attestation when it is present.
//!
//! Field-bag attributes (`attrs`) are intentionally NOT covered — they are
//! free-form metadata; the signed surface is the structural lineage edge.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::edge::{EdgeKind, LineageEdge};

/// A cryptographic proof attached to a [`LineageEdge`].
///
/// `kid` and `alg` are JWS-style identifiers so a future JWKS-backed
/// verifier can pick the right verifying key + algorithm. `sig` is the raw
/// signature bytes over [`canonical_edge_bytes`]. `prev_hash` is the SHA-256
/// of the previous edge's canonical bytes, forming a hash chain.
///
/// Wire format is JSON-stable — add fields with `#[serde(default)]` only,
/// never remove or rename existing ones.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    /// JWS key id; resolves to a verifying key via the issuer's JWKS.
    pub kid: String,
    /// JWS algorithm string (e.g., "EdDSA"). String not enum so we don't
    /// pin the verifier to a specific JWT library.
    pub alg: String,
    /// Raw signature bytes over [`canonical_edge_bytes`].
    #[serde(with = "base64_bytes")]
    pub sig: Vec<u8>,
    /// SHA-256 of the previous edge's canonical bytes (hash chain). `None`
    /// for the first edge in a log.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "opt_hash_hex"
    )]
    pub prev_hash: Option<[u8; 32]>,
}

impl Proof {
    /// Construct a Proof. Validation of the signature happens in the
    /// verifier — this constructor just builds the wire object.
    pub fn new(kid: impl Into<String>, alg: impl Into<String>, sig: Vec<u8>) -> Self {
        Self {
            kid: kid.into(),
            alg: alg.into(),
            sig,
            prev_hash: None,
        }
    }

    /// Builder: attach a previous-edge hash for chaining.
    pub fn with_prev_hash(mut self, prev_hash: [u8; 32]) -> Self {
        self.prev_hash = Some(prev_hash);
        self
    }
}

/// Compute the canonical bytes that a [`LineageEdge`]'s [`Proof`] is signed
/// over. Stable across calls. See module docs for the encoding rules.
pub fn canonical_edge_bytes(edge: &LineageEdge, prev_hash: Option<&[u8; 32]>) -> Vec<u8> {
    let mut out = Vec::with_capacity(512);
    let push_field = |out: &mut Vec<u8>, s: &str| {
        out.extend_from_slice(s.as_bytes());
        out.push(0); // NUL separator — never appears inside SPIFFE IDs (hardened parser)
    };

    push_field(&mut out, edge.child.as_str());
    push_field(&mut out, kind_tag(&edge.kind));
    for parent in &edge.parents {
        push_field(&mut out, parent.as_str());
    }
    // Empty marker between parents and the rest, so any future addition
    // of more parents doesn't shift the trailing bytes' meaning.
    out.push(0);

    if let Some(hex) = edge.content_hash_hex.as_deref() {
        out.extend_from_slice(hex.as_bytes());
    } else {
        out.extend_from_slice(&[0u8; 64]); // 64 zero ASCII bytes = "no content hash"
    }
    out.push(0);

    push_field(&mut out, &edge.ts.to_rfc3339());

    if let Some(h) = prev_hash {
        out.extend_from_slice(h);
    } else {
        out.extend_from_slice(&[0u8; 32]);
    }

    // Verifier-attestation block (added 2026-06). PURELY ADDITIVE: emitted
    // ONLY when `verifier_attestation` is `Some`. Edges without an
    // attestation (every pre-existing kind) produce byte-identical
    // canonical bytes to the pre-attestation encoding — see the module-doc
    // additive-compat invariant. When present: a single NUL delimiter then
    // 6 NUL-terminated fields; absent sub-fields emit empty bytes.
    //
    // NOTE: this diverges from the platform fork, which appends the 7-byte
    // footer unconditionally. Adopting that verbatim would change the
    // signed bytes of legacy edges, breaking the additive invariant.
    if let Some(va) = edge.verifier_attestation.as_ref() {
        out.push(0);
        let push_opt = |out: &mut Vec<u8>, s: Option<&str>| {
            if let Some(v) = s {
                out.extend_from_slice(v.as_bytes());
            }
            out.push(0);
        };
        push_opt(&mut out, va.verifier_binary_hash.as_deref());
        push_opt(&mut out, va.wasmtime_version.as_deref());
        push_opt(&mut out, va.wasmtime_config_hash.as_deref());
        push_opt(&mut out, va.vrf_params_hash.as_deref());
        push_opt(&mut out, va.external_snapshot_root.as_deref());
        push_opt(&mut out, va.lean_spec_hash.as_deref());
        // IFC egress-gate co-commit. ADDITIVE — do NOT use `push_opt` (which
        // always emits a NUL): emit nothing unless this hop was an egress-gate
        // point, so every pre-existing VA-bearing edge stays byte-identical and
        // its signature still verifies. (Verified by the additive-compat golden
        // test below.)
        if let Some(integ) = va.ifc_gated_effective_integrity.as_deref() {
            out.push(0);
            out.extend_from_slice(integ.as_bytes());
            out.push(0);
        }
        // Runner-attested running effective integrity (the gate INPUT). Same
        // additive discipline — emit nothing unless `Some`, appended after the
        // gated-co-commit block — so pre-existing VA edges stay byte-identical.
        if let Some(integ) = va.ifc_effective_integrity.as_deref() {
            out.push(0);
            out.extend_from_slice(integ.as_bytes());
            out.push(0);
        }
        // Runner/gateway-attested running effective confidentiality. Same additive
        // discipline (emit nothing unless `Some`, appended last) so pre-existing VA
        // edges stay byte-identical.
        if let Some(conf) = va.ifc_effective_confidentiality.as_deref() {
            out.push(0);
            out.extend_from_slice(conf.as_bytes());
            out.push(0);
        }
    }

    out
}

/// Compute the SHA-256 of an edge's canonical bytes — useful as a
/// `prev_hash` for the next edge in a chain.
pub fn edge_content_hash(edge: &LineageEdge, prev_hash: Option<&[u8; 32]>) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(canonical_edge_bytes(edge, prev_hash));
    h.finalize().into()
}

/// Stable string tag for an [`EdgeKind`]. Mirrors what serde would emit
/// for `#[serde(tag = "kind", rename_all = "snake_case")]`. Centralized so
/// the canonical encoding doesn't depend on serde's runtime.
fn kind_tag(kind: &EdgeKind) -> &'static str {
    match kind {
        EdgeKind::PodAdmit => "pod_admit",
        EdgeKind::ToolCall { .. } => "tool_call",
        EdgeKind::LlmCall { .. } => "llm_call",
        EdgeKind::ArtifactProduced => "artifact_produced",
        EdgeKind::Merge => "merge",
        EdgeKind::DocumentRetrieved { .. } => "document_retrieved",
        EdgeKind::Bid { .. } => "bid",
        EdgeKind::Allocation { .. } => "allocation",
        EdgeKind::ContractEvaluation { .. } => "contract_evaluation",
        EdgeKind::Dispute { .. } => "dispute",
        EdgeKind::MetricClaim { .. } => "metric_claim",
        EdgeKind::Settlement { .. } => "settlement",
        EdgeKind::Externality { .. } => "externality",
        EdgeKind::PigouvianRateUpdate { .. } => "pigouvian_rate_update",
        EdgeKind::WelfareRebate { .. } => "welfare_rebate",
        EdgeKind::Other { .. } => "other",
    }
}

// ── serde helpers ───────────────────────────────────────────────────────

mod base64_bytes {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(s).map_err(serde::de::Error::custom)
    }
}

mod opt_hash_hex {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(bytes) => s.serialize_str(&hex::encode(bytes)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
        let opt = Option::<String>::deserialize(d)?;
        match opt {
            None => Ok(None),
            Some(s) => {
                let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
                if bytes.len() != 32 {
                    return Err(serde::de::Error::custom(format!(
                        "expected 32 bytes (64 hex chars), got {}",
                        bytes.len()
                    )));
                }
                let mut out = [0u8; 32];
                out.copy_from_slice(&bytes);
                Ok(Some(out))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edge::{EdgeKind, LineageEdge, VerifierAttestation};
    use crate::id::CallSpiffeId;

    fn pod() -> CallSpiffeId {
        CallSpiffeId::pod("prod.example.com", "agents", "coder").unwrap()
    }

    #[test]
    fn proof_round_trips_through_json() {
        let p = Proof::new("kid-abc", "EdDSA", vec![1, 2, 3, 4, 5]).with_prev_hash([0xAA; 32]);
        let json = serde_json::to_string(&p).unwrap();
        let back: Proof = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn proof_skips_prev_hash_when_none() {
        let p = Proof::new("kid", "EdDSA", vec![1, 2, 3]);
        let json = serde_json::to_string(&p).unwrap();
        assert!(!json.contains("prev_hash"));
    }

    #[test]
    fn canonical_bytes_are_deterministic() {
        let p = pod();
        let child = p.derive_tool("Bash", Some(b"x")).unwrap();
        let edge = LineageEdge::from_parent(
            child,
            p,
            EdgeKind::ToolCall {
                tool: "Bash".to_string(),
            },
        );
        let bytes1 = canonical_edge_bytes(&edge, None);
        let bytes2 = canonical_edge_bytes(&edge, None);
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn canonical_bytes_change_if_child_changes() {
        let p = pod();
        let edge_a = LineageEdge::from_parent(
            p.derive_tool("Bash", Some(b"a")).unwrap(),
            p.clone(),
            EdgeKind::ToolCall {
                tool: "Bash".to_string(),
            },
        );
        let edge_b = LineageEdge::from_parent(
            p.derive_tool("Bash", Some(b"b")).unwrap(),
            p,
            EdgeKind::ToolCall {
                tool: "Bash".to_string(),
            },
        );
        assert_ne!(
            canonical_edge_bytes(&edge_a, None),
            canonical_edge_bytes(&edge_b, None)
        );
    }

    #[test]
    fn canonical_bytes_change_if_prev_hash_changes() {
        let p = pod();
        let child = p.derive_tool("Bash", Some(b"x")).unwrap();
        let edge = LineageEdge::from_parent(
            child,
            p,
            EdgeKind::ToolCall {
                tool: "Bash".to_string(),
            },
        );
        let bytes_none = canonical_edge_bytes(&edge, None);
        let bytes_some = canonical_edge_bytes(&edge, Some(&[0xAA; 32]));
        assert_ne!(bytes_none, bytes_some);
    }

    /// Additive-compat golden for the IFC egress co-commit (THE trap this rung
    /// exists to avoid): adding `ifc_gated_effective_integrity` must emit ZERO
    /// bytes when `None`, so every pre-existing VA-bearing edge canonicalizes
    /// byte-identically and its signature still verifies. We prove it by showing
    /// the `None` encoding is a strict PREFIX of the `Some` encoding (the VA
    /// block is the last thing emitted), and the delta is exactly the gated
    /// field.
    #[test]
    fn egress_cocommit_is_purely_additive() {
        use crate::edge::VerifierAttestation;
        let p = pod();
        let child = p.derive_tool("web_post", Some(b"x")).unwrap();
        let va_base = VerifierAttestation::new().with_lean_spec_hash("deadbeef");
        // Build ONE edge, then clone + swap only the VA's egress field — so `ts`
        // (stamped at construction) is identical and the only difference is the
        // co-commit field.
        let edge_none = LineageEdge::from_parent(
            child,
            p,
            EdgeKind::ToolCall {
                tool: "web_post".to_string(),
            },
        )
        .with_verifier_attestation(va_base.clone());
        let mut edge_some = edge_none.clone();
        edge_some.verifier_attestation =
            Some(va_base.with_ifc_gated_effective_integrity("trusted"));

        let bytes_none = canonical_edge_bytes(&edge_none, None);
        let bytes_some = canonical_edge_bytes(&edge_some, None);

        // `None` adds nothing; `Some` appends exactly `\0trusted\0`.
        assert!(
            bytes_some.starts_with(&bytes_none),
            "the absent-field encoding must be a prefix => purely additive"
        );
        let mut expected_delta = vec![0u8];
        expected_delta.extend_from_slice(b"trusted");
        expected_delta.push(0);
        assert_eq!(
            &bytes_some[bytes_none.len()..],
            &expected_delta[..],
            "the only added bytes are the gated field's"
        );
    }

    /// Same additive-compat guarantee for the runner-attested
    /// `ifc_effective_integrity` (the gate-INPUT label): `None` emits zero bytes;
    /// `Some` appends exactly the field. Guards the same signature-breaking trap.
    #[test]
    fn effective_integrity_is_purely_additive() {
        use crate::edge::VerifierAttestation;
        let p = pod();
        let child = p.derive_tool("web_post", Some(b"x")).unwrap();
        let va_base = VerifierAttestation::new().with_lean_spec_hash("deadbeef");
        let edge_none = LineageEdge::from_parent(
            child,
            p,
            EdgeKind::ToolCall {
                tool: "web_post".to_string(),
            },
        )
        .with_verifier_attestation(va_base.clone());
        let mut edge_some = edge_none.clone();
        edge_some.verifier_attestation = Some(va_base.with_ifc_effective_integrity("adversarial"));

        let bytes_none = canonical_edge_bytes(&edge_none, None);
        let bytes_some = canonical_edge_bytes(&edge_some, None);
        assert!(
            bytes_some.starts_with(&bytes_none),
            "absent field => prefix => purely additive"
        );
        let mut expected_delta = vec![0u8];
        expected_delta.extend_from_slice(b"adversarial");
        expected_delta.push(0);
        assert_eq!(&bytes_some[bytes_none.len()..], &expected_delta[..]);
    }

    /// Same additive-compat guarantee for the signed `ifc_effective_confidentiality`
    /// field (the conf-axis grounding): `None` emits zero bytes; `Some` appends
    /// exactly the field.
    #[test]
    fn effective_confidentiality_is_purely_additive() {
        use crate::edge::VerifierAttestation;
        let p = pod();
        let child = p.derive_tool("web_post", Some(b"x")).unwrap();
        let va_base = VerifierAttestation::new().with_lean_spec_hash("deadbeef");
        let edge_none = LineageEdge::from_parent(
            child,
            p,
            EdgeKind::ToolCall {
                tool: "web_post".to_string(),
            },
        )
        .with_verifier_attestation(va_base.clone());
        let mut edge_some = edge_none.clone();
        edge_some.verifier_attestation = Some(va_base.with_ifc_effective_confidentiality("secret"));

        let bytes_none = canonical_edge_bytes(&edge_none, None);
        let bytes_some = canonical_edge_bytes(&edge_some, None);
        assert!(
            bytes_some.starts_with(&bytes_none),
            "absent field => prefix => purely additive"
        );
        let mut expected_delta = vec![0u8];
        expected_delta.extend_from_slice(b"secret");
        expected_delta.push(0);
        assert_eq!(&bytes_some[bytes_none.len()..], &expected_delta[..]);
    }

    #[test]
    fn edge_content_hash_is_deterministic_and_32_bytes() {
        let p = pod();
        let child = p.derive_artifact(b"hello").unwrap();
        let edge = LineageEdge::from_parent(child, p, EdgeKind::ArtifactProduced);
        let h1 = edge_content_hash(&edge, None);
        let h2 = edge_content_hash(&edge, None);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 32);
    }

    #[test]
    fn prev_hash_chains_via_canonical_bytes() {
        let p = pod();
        let edge1 = LineageEdge::from_parent(
            p.derive_tool("Bash", Some(b"1")).unwrap(),
            p.clone(),
            EdgeKind::ToolCall {
                tool: "Bash".to_string(),
            },
        );
        let h1 = edge_content_hash(&edge1, None);

        let edge2 = LineageEdge::from_parent(
            p.derive_tool("Bash", Some(b"2")).unwrap(),
            p,
            EdgeKind::ToolCall {
                tool: "Bash".to_string(),
            },
        );
        let h2_chained = edge_content_hash(&edge2, Some(&h1));
        let h2_unchained = edge_content_hash(&edge2, None);
        assert_ne!(h2_chained, h2_unchained, "chain must affect hash");
    }

    #[test]
    fn pod_admit_canonical_bytes_have_no_parents() {
        let edge = LineageEdge::pod_admit(pod());
        let bytes = canonical_edge_bytes(&edge, None);
        // child + kind tag should be present
        assert!(bytes
            .windows(7)
            .any(|w| w == b"agents/" || w == b"sa/code" || w.starts_with(b"spiffe:")));
    }

    // ── Additive-compatibility invariant ────────────────────────────────

    /// **LOAD-BEARING.** The verifier-attestation merge is PURELY ADDITIVE:
    /// an edge with `verifier_attestation: None` (every pre-existing kind:
    /// PodAdmit/ToolCall/LlmCall/ArtifactProduced/Merge/DocumentRetrieved/
    /// Other) MUST produce canonical bytes that END exactly at the 32-byte
    /// prev_hash slot — i.e. byte-identical to the pre-attestation encoding.
    ///
    /// This is verified structurally: a VA=None edge's bytes have NO footer.
    /// The bytes are reconstructed independently from the documented field
    /// order (child, kind, parents, marker, content-hash, ts, prev_hash) and
    /// compared for full equality. If a future change appends a footer to
    /// VA=None edges, this test fails — that is the regression guard.
    #[test]
    fn va_none_edge_has_no_footer_and_matches_legacy_encoding() {
        use chrono::TimeZone;
        let p = pod();
        let mut edge = LineageEdge::pod_admit(p);
        edge.ts = chrono::Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        assert!(edge.verifier_attestation.is_none());

        let bytes = canonical_edge_bytes(&edge, None);

        // Recompute the legacy (pre-attestation) encoding by hand and assert
        // full byte-equality. This pins the exact signed surface for every
        // pre-existing edge kind.
        let mut expected: Vec<u8> = Vec::new();
        // child
        expected.extend_from_slice(edge.child.as_str().as_bytes());
        expected.push(0);
        // kind tag (pod_admit)
        expected.extend_from_slice(b"pod_admit");
        expected.push(0);
        // parents: none → just the empty marker NUL
        expected.push(0);
        // content hash: absent → 64 zero ASCII bytes, then NUL
        expected.extend_from_slice(&[0u8; 64]);
        expected.push(0);
        // ts
        expected.extend_from_slice(edge.ts.to_rfc3339().as_bytes());
        expected.push(0);
        // prev_hash: none → 32 zero bytes
        expected.extend_from_slice(&[0u8; 32]);
        // NO footer for VA=None.

        assert_eq!(
            bytes, expected,
            "VA=None edge must produce byte-identical legacy canonical bytes \
             (no attestation footer) — the additive-compat invariant"
        );
        // And the last 32 bytes are exactly the prev_hash slot (no trailing
        // footer bytes after it).
        let len = bytes.len();
        assert_eq!(&bytes[len - 32..], &[0u8; 32]);
    }

    /// Toggling `verifier_attestation` from `None` to `Some(empty)` MUST
    /// change the canonical bytes under the gated encoding (an empty-but-
    /// present attestation adds the 7-byte footer). This is the deliberate
    /// divergence from the platform fork's `empty_va_field_equivalent_to_none`
    /// invariant: in the additive design, presence of the attestation object
    /// is itself binding.
    #[test]
    fn va_some_empty_adds_seven_byte_footer() {
        use chrono::TimeZone;
        let p = pod();
        let mut e_none = LineageEdge::pod_admit(p.clone());
        e_none.ts = chrono::Utc.timestamp_opt(1_700_000_000, 0).unwrap();

        let e_empty = e_none
            .clone()
            .with_verifier_attestation(VerifierAttestation::new());

        let bytes_none = canonical_edge_bytes(&e_none, None);
        let bytes_empty = canonical_edge_bytes(&e_empty, None);

        assert_ne!(bytes_none, bytes_empty);
        // Footer = 1 delimiter NUL + 6 empty fields × 1 NUL each = 7 bytes.
        assert_eq!(bytes_empty.len(), bytes_none.len() + 7);
        assert_eq!(&bytes_empty[bytes_empty.len() - 7..], &[0u8; 7]);
        // The prefix (everything before the footer) is byte-identical to the
        // VA=None encoding — additivity at the byte level.
        assert_eq!(&bytes_empty[..bytes_none.len()], &bytes_none[..]);
    }

    /// A populated `VerifierAttestation` binds each field positionally: the
    /// same hex value in different fields yields different canonical bytes,
    /// and a populated attestation extends (never rewrites) the VA=None
    /// prefix.
    #[test]
    fn va_some_populated_binds_fields_positionally() {
        let p = pod();
        let base = LineageEdge::from_parent(
            p.derive_artifact(b"x").unwrap(),
            p,
            EdgeKind::MetricClaim {
                metric_name: "gini".into(),
                window_id: "2026-05".into(),
            },
        )
        .with_content_hash("0".repeat(64));

        let none_bytes = canonical_edge_bytes(&base, None);

        let with_lean = base.clone().with_verifier_attestation(
            VerifierAttestation::new().with_lean_spec_hash("a".repeat(64)),
        );
        let with_vrf = base.clone().with_verifier_attestation(
            VerifierAttestation::new().with_vrf_params_hash("a".repeat(64)),
        );

        let b_lean = canonical_edge_bytes(&with_lean, None);
        let b_vrf = canonical_edge_bytes(&with_vrf, None);

        // Same value, different field → different bytes (positional binding).
        assert_ne!(b_lean, b_vrf);
        // Both extend the VA=None prefix verbatim.
        assert_eq!(&b_lean[..none_bytes.len()], &none_bytes[..]);
        assert_eq!(&b_vrf[..none_bytes.len()], &none_bytes[..]);
    }
}
