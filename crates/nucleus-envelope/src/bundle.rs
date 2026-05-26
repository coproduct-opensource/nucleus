//! [`Bundle`] and [`Envelope`] — the on-wire types and their builder.

use chrono::{DateTime, Utc};
use nucleus_lineage::{
    edge_content_hash, CallSpiffeId, EdgeSigner, IdError, IssuerError, Jwks, LineageEdge,
    LineageSink, MerkleProver, SignedTreeHead, WitnessClient,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::binding::{
    payload_hash, signed_bytes as binding_signed_bytes, BindingError, PayloadBinding,
    NUCLEUS_BUNDLE_PAYLOAD_TYPE,
};
use crate::extract;

/// Errors a [`BundleBuilder`] may surface.
#[derive(Debug, Error)]
pub enum BundleError {
    /// Subgraph extraction failed while reading the underlying sink.
    #[error("lineage sink error: {0}")]
    Sink(#[from] nucleus_lineage::SinkError),
    /// The session root SPIFFE id was invalid.
    #[error("invalid session root id: {0}")]
    InvalidId(#[from] IdError),
    /// No edges were found for the supplied session root. A bundle with an
    /// empty envelope is rarely useful and almost always indicates a bug,
    /// so the builder refuses by default.
    #[error("no lineage edges found under session root {0}")]
    EmptySession(String),
    /// Required builder field was not set before `build()`.
    #[error("missing required builder field: {0}")]
    MissingField(&'static str),
    /// Builder was configured with `require_signed()` but at least one
    /// session edge lacked a cryptographic `proof`. Surfaced at build
    /// time so producers learn early, instead of at the verifier.
    #[error("edge #{index} has no proof; require_signed() rejects mixed logs")]
    UnsignedEdge { index: usize },
    /// `with_merkle_prover()` was set but the prover could not locate
    /// the leaf for edge #{index} (its content hash was not emitted
    /// into the Merkle tree). Indicates a sink/prover mismatch — the
    /// edges in the regular sink don't match what the Merkle tree
    /// committed to.
    #[error(
        "edge #{index} content_hash not found in Merkle prover; sink and prover are out of sync"
    )]
    MerkleProverMissingLeaf { index: usize },
    /// Sealing the current root via the witness failed.
    #[error("Merkle anchor seal failed: {0}")]
    MerkleAnchorSeal(String),
    /// An external witness refused to countersign the sealed STH.
    #[error("witness cosignature failed: {0}")]
    Cosign(String),
    /// Computing or signing the payload binding failed.
    #[error("payload binding: {0}")]
    Binding(#[from] BindingError),
    /// The binding signer's `sign` method returned an error.
    #[error("payload binding signer: {0}")]
    BindingSigner(#[from] IssuerError),
}

/// A portable, self-contained provenance bundle.
///
/// `payload` is the agent's structured output (free-form JSON — typically
/// `{"stats": ..., "summary": ...}`). `envelope` is the IFC certificate
/// that lets anyone re-validate the payload's provenance without trusting
/// the producer's storage.
///
/// Wire format is JSON; field order is stable across serde versions. New
/// fields must be `#[serde(default)]` to preserve forward compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bundle {
    /// Agent payload — opaque JSON.
    pub payload: Value,
    /// Provenance envelope covering the payload's session.
    pub envelope: Envelope,
    /// **v2.2 payload binding.** Detached DSSE-style signature that
    /// ties the `payload` bytes to the envelope's chain head (and
    /// Merkle root, when v2). Present when the producer called
    /// [`BundleBuilder::with_binding_signer`]; absent for older v1/v2
    /// bundles. Verifiers MAY require it via
    /// `TrustAnchor::require_payload_binding`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<PayloadBinding>,
}

/// The provenance certificate accompanying a [`Bundle::payload`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    /// Pod / session root SPIFFE id — the URI prefix under which every
    /// edge in this envelope was emitted.
    pub session_root: CallSpiffeId,
    /// Session subgraph in linear chain order. Verification is performed
    /// in this order; each edge's `proof.prev_hash` must match the
    /// previous edge's `edge_content_hash`.
    pub edges: Vec<LineageEdge>,
    /// JSON Web Key Set covering every `proof.kid` that appears in
    /// `edges`. Embedded so a verifier needs no network calls.
    pub jwks: Jwks,
    /// Signed tree heads contemporaneous with this session (zero or more).
    /// In v1 these are *time attestations* — full Merkle inclusion proof
    /// binding `edges` to a `root_hash` is via [`Self::merkle_anchor`].
    #[serde(default)]
    pub checkpoints: Vec<SignedTreeHead>,
    /// **v2 trust extension**: signed tree head + per-edge inclusion
    /// proofs that bind every entry in `edges` to a Merkle root the
    /// witness has signed. When `Some`, a verifier with a trust anchor
    /// that includes the witness pubkey can cryptographically check
    /// that these specific edges are committed in the witness's log.
    ///
    /// Absent (`None`) means the bundle was produced without a
    /// Merkle-backed sink — `verify_bundle` will fall back to the v1
    /// chain-only check and the trust mode reports that.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merkle_anchor: Option<MerkleAnchor>,
    /// Envelope metadata (creation time, schema version, …).
    pub meta: EnvelopeMeta,
}

/// Cryptographic binding between session edges and a witness-signed
/// Merkle root. The presence of this field upgrades the bundle from
/// "chain-only" integrity to "chain + transparency-log inclusion."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleAnchor {
    /// Signed tree head the inclusion proofs are anchored to. Its
    /// signature is verified against the trust anchor's witness
    /// pubkey; its `root_hash_hex` is the root that every inclusion
    /// proof must reproduce when fed its corresponding leaf.
    pub sth: SignedTreeHead,
    /// One inclusion proof per edge in `Envelope::edges`, in the same
    /// order. `inclusion_proofs[i]` proves that `edge_content_hash`
    /// of `edges[i]` sits at `leaf_index` in the tree whose root is
    /// `sth.root_hash_hex`.
    pub inclusion_proofs: Vec<EdgeInclusionProof>,
}

/// One RFC 6962 inclusion proof, wire-encoded as the leaf index plus
/// the audit path (concatenated 32-byte SHA-256 nodes, hex).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeInclusionProof {
    /// Index of this edge's leaf in the witness's Merkle tree.
    pub leaf_index: u64,
    /// RFC 6962 audit path: concatenated sibling-node hashes from
    /// leaf to root, hex-encoded. Each 32 bytes = 64 hex chars.
    pub audit_path_hex: String,
}

/// Metadata about the envelope itself (not about the payload it covers).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeMeta {
    /// Envelope schema version. Bump on any breaking change to the wire
    /// format; verifiers may refuse unknown versions.
    pub schema_version: u32,
    /// Wall-clock time the bundle was assembled.
    pub created_at: DateTime<Utc>,
}

/// Current envelope schema version. Verifiers should accept this and
/// reject (or migrate) anything newer than they understand.
pub const ENVELOPE_SCHEMA_VERSION: u32 = 1;

impl EnvelopeMeta {
    /// Default metadata stamped with the current time and current schema
    /// version.
    pub fn now() -> Self {
        Self {
            schema_version: ENVELOPE_SCHEMA_VERSION,
            created_at: Utc::now(),
        }
    }
}

/// Builder for [`Bundle`]. Required fields: `payload`, `sink`, `jwks`.
/// `checkpoints` is optional and defaults to empty.
pub struct BundleBuilder<'a> {
    session_root: CallSpiffeId,
    payload: Option<Value>,
    sink: Option<&'a dyn LineageSink>,
    jwks: Option<Jwks>,
    checkpoints: Vec<SignedTreeHead>,
    allow_empty: bool,
    require_signed: bool,
    /// Optional Merkle prover. When supplied, the builder seals the
    /// current Merkle root via the prover's witness and emits a
    /// per-edge inclusion proof, producing a v2 bundle.
    merkle_prover: Option<&'a dyn MerkleProver>,
    /// Optional external witnesses to countersign the sealed STH
    /// (v2.1 federation). Each witness's [`WitnessClient::cosign`] is
    /// invoked once after the STH is sealed; results land in
    /// `sth.cosignatures`. Ignored if `merkle_prover` is `None`.
    cosignatories: Vec<&'a dyn WitnessClient>,
    /// Optional binding signer (v2.2). When supplied, the builder
    /// produces a [`PayloadBinding`] that authenticates the payload
    /// bytes against the envelope head + Merkle root (if v2).
    binding_signer: Option<&'a dyn EdgeSigner>,
}

impl<'a> BundleBuilder<'a> {
    /// Begin a new bundle for the session rooted at `session_root`.
    pub fn new(session_root: CallSpiffeId) -> Self {
        Self {
            session_root,
            payload: None,
            sink: None,
            jwks: None,
            checkpoints: Vec::new(),
            allow_empty: false,
            require_signed: false,
            merkle_prover: None,
            cosignatories: Vec::new(),
            binding_signer: None,
        }
    }

    /// Set the agent-produced payload (free-form JSON).
    pub fn payload(mut self, payload: Value) -> Self {
        self.payload = Some(payload);
        self
    }

    /// Source of lineage edges — typically the same sink the session
    /// wrote into.
    pub fn sink(mut self, sink: &'a dyn LineageSink) -> Self {
        self.sink = Some(sink);
        self
    }

    /// JSON Web Key Set covering every issuer that signed edges in this
    /// session. Required for the verifier to validate proofs offline.
    pub fn jwks(mut self, jwks: Jwks) -> Self {
        self.jwks = Some(jwks);
        self
    }

    /// Attach contemporaneous signed tree heads. Time attestations in v1.
    pub fn checkpoints(mut self, checkpoints: Vec<SignedTreeHead>) -> Self {
        self.checkpoints = checkpoints;
        self
    }

    /// Allow building a bundle whose envelope contains zero session
    /// edges. Off by default. The verifier will *also* reject empty
    /// envelopes unless [`crate::TrustAnchor::allow_empty`] is set —
    /// the builder permission does not override the verifier's.
    pub fn allow_empty(mut self) -> Self {
        self.allow_empty = true;
        self
    }

    /// Refuse to build if any edge in the session subgraph lacks a
    /// cryptographic `proof`. Surfaces the failure at packaging time
    /// rather than letting the verifier discover it later.
    pub fn require_signed(mut self) -> Self {
        self.require_signed = true;
        self
    }

    /// Attach a Merkle prover. The builder will seal the prover's
    /// current root via its witness and emit per-edge inclusion
    /// proofs. The resulting bundle's [`Envelope::merkle_anchor`] is
    /// `Some`; a verifier with the witness pubkey in its trust anchor
    /// will check both per-edge signatures AND tree-inclusion.
    pub fn with_merkle_prover(mut self, prover: &'a dyn MerkleProver) -> Self {
        self.merkle_prover = Some(prover);
        self
    }

    /// Attach a set of external [`WitnessClient`]s that will be asked
    /// to countersign the sealed STH (v2.1 witness federation). The
    /// resulting STH carries one [`Cosignature`] per witness; a
    /// verifier configured with a trusted-witness set + threshold
    /// rejects bundles below threshold.
    ///
    /// No-op when no Merkle prover is attached — cosignatures need
    /// something to sign over.
    ///
    /// [`Cosignature`]: nucleus_lineage::Cosignature
    pub fn with_cosignatures(mut self, witnesses: Vec<&'a dyn WitnessClient>) -> Self {
        self.cosignatories = witnesses;
        self
    }

    /// **v2.2 payload binding.** Attach a signer that will produce a
    /// [`PayloadBinding`] over the payload + envelope head (+ Merkle
    /// root, when v2). Verifiers with the corresponding kid in their
    /// trust JWKS can detect payload-only tampering — closes the v1
    /// documented limitation. The signer's `kid` becomes the binding's
    /// `keyid`; in practice, callers re-use the same `EdgeSigner` that
    /// produced the per-edge proofs.
    pub fn with_binding_signer(mut self, signer: &'a dyn EdgeSigner) -> Self {
        self.binding_signer = Some(signer);
        self
    }

    /// Assemble the [`Bundle`].
    pub fn build(self) -> Result<Bundle, BundleError> {
        let payload = self.payload.ok_or(BundleError::MissingField("payload"))?;
        let sink = self.sink.ok_or(BundleError::MissingField("sink"))?;
        let jwks = self.jwks.ok_or(BundleError::MissingField("jwks"))?;

        let subgraph = extract::extract_session_subgraph(&self.session_root, sink)?;
        if subgraph.edges.is_empty() && !self.allow_empty {
            return Err(BundleError::EmptySession(self.session_root.to_string()));
        }
        if self.require_signed {
            if let Some(index) = subgraph.edges.iter().position(|e| e.proof.is_none()) {
                return Err(BundleError::UnsignedEdge { index });
            }
        }

        // v2: if a Merkle prover was supplied, gather inclusion proofs
        // and seal the root ATOMICALLY (one prover-lock acquisition).
        //
        // CRIT-1 from the second skeptical audit: the non-atomic path
        // (prove_for_hash + seal_current_root in sequence) leaks a race
        // where concurrent emit advances the tree between the two calls,
        // producing proofs that don't verify against the sealed root.
        // `MerkleProver::prove_for_hashes_and_seal` collapses both into
        // one critical section.
        let merkle_anchor = if let Some(prover) = self.merkle_prover {
            let leaf_hashes: Vec<[u8; 32]> = subgraph
                .edges
                .iter()
                .map(|e| edge_content_hash(e, None))
                .collect();
            let (mut sth, raw_proofs) =
                prover
                    .prove_for_hashes_and_seal(&leaf_hashes)
                    .map_err(|e| {
                        // Distinguish "leaf not in tree" (sink/prover mismatch)
                        // from genuine seal failures. The atomic call wraps
                        // missing-leaf errors as MerkleError::Witness today;
                        // surface a clearer message either way.
                        BundleError::MerkleAnchorSeal(e.to_string())
                    })?;
            let inclusion_proofs = raw_proofs
                .into_iter()
                .map(|(leaf_index, proof)| EdgeInclusionProof {
                    leaf_index,
                    audit_path_hex: hex::encode(proof.as_bytes()),
                })
                .collect();

            // v2.1 witness federation: ask each external witness to
            // countersign the sealed STH. Failures are surfaced as
            // BundleError::Cosign so a missing witness doesn't silently
            // ship a partial bundle.
            for witness in &self.cosignatories {
                let cosig = witness
                    .cosign(&sth)
                    .map_err(|e| BundleError::Cosign(e.to_string()))?;
                sth.cosignatures.push(cosig);
            }
            Some(MerkleAnchor {
                sth,
                inclusion_proofs,
            })
        } else {
            None
        };

        let envelope = Envelope {
            session_root: subgraph.root,
            edges: subgraph.edges,
            jwks,
            checkpoints: self.checkpoints,
            merkle_anchor,
            meta: EnvelopeMeta::now(),
        };

        // v2.2 payload binding (optional). The binding signature
        // covers (sha256(payload) || envelope_head_hash || merkle_root)
        // via DSSE PAE so a downstream verifier can detect payload
        // tampering even when every per-edge signature still checks.
        let binding = if let Some(signer) = self.binding_signer {
            let payload_h = payload_hash(&payload)?;
            let head_hash = compute_envelope_head_hash(&envelope.edges);
            let merkle_root_bytes: Option<[u8; 32]> =
                envelope.merkle_anchor.as_ref().and_then(|a| {
                    hex::decode(&a.sth.root_hash_hex)
                        .ok()
                        .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
                });
            let to_sign = binding_signed_bytes(
                NUCLEUS_BUNDLE_PAYLOAD_TYPE,
                &payload_h,
                &head_hash,
                merkle_root_bytes.as_ref(),
            );
            let signature = signer.sign(&to_sign)?;
            Some(PayloadBinding {
                payload_type: NUCLEUS_BUNDLE_PAYLOAD_TYPE.to_string(),
                payload_hash_hex: hex::encode(payload_h),
                envelope_head_hash_hex: hex::encode(head_hash),
                merkle_root_hex: merkle_root_bytes.map(hex::encode),
                keyid: signer.kid().to_string(),
                signature,
            })
        } else {
            None
        };

        Ok(Bundle {
            payload,
            envelope,
            binding,
        })
    }
}

/// Compute the SHA-256 of the head (last) edge's canonical bytes,
/// chained from index 0. Mirrors what `verify_bundle`'s
/// `head_edge_hash_hex` reports. Returns all-zeros for empty input.
pub(crate) fn compute_envelope_head_hash(edges: &[LineageEdge]) -> [u8; 32] {
    let mut prev: Option<[u8; 32]> = None;
    let mut last = [0u8; 32];
    for edge in edges {
        let h = nucleus_lineage::edge_content_hash(edge, prev.as_ref());
        last = h;
        prev = Some(h);
    }
    last
}

#[cfg(test)]
mod tests {
    use super::*;
    use nucleus_lineage::{EdgeKind, InMemorySink};

    fn pod() -> CallSpiffeId {
        CallSpiffeId::pod("prod.example.com", "agents", "summarizer").unwrap()
    }

    #[test]
    fn schema_version_constant_matches_default_meta() {
        let m = EnvelopeMeta::now();
        assert_eq!(m.schema_version, ENVELOPE_SCHEMA_VERSION);
    }

    #[test]
    fn builder_missing_payload_errors() {
        let sink = InMemorySink::new();
        let err = BundleBuilder::new(pod())
            .sink(&sink)
            .jwks(Jwks { keys: vec![] })
            .build()
            .unwrap_err();
        assert!(matches!(err, BundleError::MissingField("payload")));
    }

    #[test]
    fn builder_missing_sink_errors() {
        let err = BundleBuilder::new(pod())
            .payload(serde_json::json!({}))
            .jwks(Jwks { keys: vec![] })
            .build()
            .unwrap_err();
        assert!(matches!(err, BundleError::MissingField("sink")));
    }

    #[test]
    fn builder_missing_jwks_errors() {
        let sink = InMemorySink::new();
        let err = BundleBuilder::new(pod())
            .payload(serde_json::json!({}))
            .sink(&sink)
            .build()
            .unwrap_err();
        assert!(matches!(err, BundleError::MissingField("jwks")));
    }

    #[test]
    fn builder_empty_session_errors_by_default() {
        let sink = InMemorySink::new();
        let err = BundleBuilder::new(pod())
            .payload(serde_json::json!({}))
            .sink(&sink)
            .jwks(Jwks { keys: vec![] })
            .build()
            .unwrap_err();
        assert!(matches!(err, BundleError::EmptySession(_)));
    }

    #[test]
    fn builder_allow_empty_accepts_zero_edges() {
        let sink = InMemorySink::new();
        let bundle = BundleBuilder::new(pod())
            .payload(serde_json::json!({"stats": 0}))
            .sink(&sink)
            .jwks(Jwks { keys: vec![] })
            .allow_empty()
            .build()
            .unwrap();
        assert!(bundle.envelope.edges.is_empty());
        assert_eq!(bundle.envelope.meta.schema_version, ENVELOPE_SCHEMA_VERSION);
    }

    #[test]
    fn bundle_round_trips_through_json() {
        let sink = InMemorySink::new();
        let p = pod();
        sink.emit(LineageEdge::pod_admit(p.clone())).unwrap();
        sink.emit(LineageEdge::from_parent(
            p.derive_tool("Read", Some(b"hello")).unwrap(),
            p.clone(),
            EdgeKind::ToolCall {
                tool: "Read".to_string(),
            },
        ))
        .unwrap();

        let bundle = BundleBuilder::new(p)
            .payload(serde_json::json!({"summary": "hi", "stats": {"bytes": 5}}))
            .sink(&sink)
            .jwks(Jwks { keys: vec![] })
            .build()
            .unwrap();
        assert_eq!(bundle.envelope.edges.len(), 2);

        let json = serde_json::to_string(&bundle).unwrap();
        let back: Bundle = serde_json::from_str(&json).unwrap();
        assert_eq!(back.envelope.edges.len(), 2);
        assert_eq!(back.envelope.session_root, bundle.envelope.session_root);
        assert_eq!(back.payload, bundle.payload);
    }
}
