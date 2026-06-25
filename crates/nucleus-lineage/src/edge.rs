//! [`LineageEdge`] — one entry in the append-only lineage DAG.
//!
//! Each edge records a single act of derivation: a child identity (one or
//! more) [`CallSpiffeId`]s flowed into it. Edges are content-addressable
//! records; the in-memory and JSONL sinks both treat them as immutable.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::id::CallSpiffeId;
use crate::proof::Proof;

/// Pins the verification environment that an edge's claim can be
/// independently recomputed against. The off-platform verification closure
/// depends on this metadata being part of the signed surface — without it,
/// "independently recomputable" is rhetoric (the operator could swap
/// verifier binaries, Wasmtime versions, VRF parameters, or Lean specs
/// between claim production and recomputation).
///
/// All-`None` is the unattested case (legacy edges, structural-only claims).
/// Economic-edge variants — `Bid`, `Allocation`, `ContractEvaluation`,
/// `Dispute`, `MetricClaim` — SHOULD populate the relevant fields when
/// signed. Each field is its own `Option<String>` so callers can attest
/// partially (e.g., a `MetricClaim` without VRF dependency leaves
/// `vrf_params_hash` unset).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierAttestation {
    /// Identity tag of the verifier binary that recomputes this claim.
    ///
    /// **Two accepted forms** (iteration-12 audit fix #6):
    /// - **Semver-versioned package id**: `"<crate-name>@<semver>"`
    ///   (e.g. `"nucleus-runner@0.1.0"`). This is what the runner stamps
    ///   today — sufficient for verifier replay because the source
    ///   tree at a given semver IS content-addressable via the Cargo
    ///   ecosystem (Cargo.lock + the source tarball's hash on
    ///   crates.io).
    /// - **64-char hex SHA-256**: of the published binary itself, for
    ///   verifiers that prefer binary-equality over semver-trust.
    ///
    /// Both forms are accepted because semver pinning is sufficient
    /// for the substrate's "rebuild from source at this commit"
    /// replay model. A future emitter that hashes a sealed,
    /// reproducible binary may use the hex form; today's emitters
    /// use the `@` form.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier_binary_hash: Option<String>,
    /// Wasmtime version + config descriptor (e.g., "44.0.0+nan_canon+fuel=off").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wasmtime_version: Option<String>,
    /// Hex hash of the relevant Wasmtime config bundle (host functions,
    /// resource limits, NaN canonicalization) that affect determinism.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wasmtime_config_hash: Option<String>,
    /// Hex hash of VRF public parameters when the claim depends on a VRF
    /// (e.g., arbitrator panel selection in Primitive 4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vrf_params_hash: Option<String>,
    /// Hex Merkle root of external state snapshot (e.g., trust-service
    /// reputation state) at claim time, for closures that depend on
    /// stateful external services.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_snapshot_root: Option<String>,
    /// Hex hash of the Lean spec module that pinned the property this claim
    /// satisfies (e.g., `formal/Nucleus/Auctions/BudgetConservation.lean`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lean_spec_hash: Option<String>,
    /// Present iff this hop was an IFC egress-gate point (the invoked tool had a
    /// non-empty `egress_allowlist`) AND the gate ALLOWED it; the value is the
    /// chain effective integrity the gate evaluated. **Presence encodes "was
    /// egress-gated"; absence means "not an egress hop."** A signed edge whose
    /// value is `Some("adversarial")` (or an unrecognized token) is
    /// self-inconsistent — the gateway would have *denied*, producing no edge —
    /// which `nucleus_recompute::verify_ifc_flow` flags. Signature-covered (it
    /// rides in `canonical_edge_bytes`), so it cannot be altered post-signing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ifc_gated_effective_integrity: Option<String>,
}

impl VerifierAttestation {
    /// Construct an empty attestation; populate fields via builder methods.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder: pin the verifier binary hash.
    pub fn with_verifier_binary_hash(mut self, hex: impl Into<String>) -> Self {
        self.verifier_binary_hash = Some(hex.into());
        self
    }

    /// Builder: pin the Wasmtime version descriptor.
    pub fn with_wasmtime_version(mut self, version: impl Into<String>) -> Self {
        self.wasmtime_version = Some(version.into());
        self
    }

    /// Builder: pin the Wasmtime config bundle hash.
    pub fn with_wasmtime_config_hash(mut self, hex: impl Into<String>) -> Self {
        self.wasmtime_config_hash = Some(hex.into());
        self
    }

    /// Builder: pin the VRF public parameters hash.
    pub fn with_vrf_params_hash(mut self, hex: impl Into<String>) -> Self {
        self.vrf_params_hash = Some(hex.into());
        self
    }

    /// Builder: pin the external-state-snapshot root.
    pub fn with_external_snapshot_root(mut self, hex: impl Into<String>) -> Self {
        self.external_snapshot_root = Some(hex.into());
        self
    }

    /// Builder: pin the Lean spec module hash.
    pub fn with_lean_spec_hash(mut self, hex: impl Into<String>) -> Self {
        self.lean_spec_hash = Some(hex.into());
        self
    }

    /// Builder: record the IFC egress-gate co-commit (the effective integrity
    /// the gate allowed this egress hop under). See the field docs.
    pub fn with_ifc_gated_effective_integrity(mut self, integ: impl Into<String>) -> Self {
        self.ifc_gated_effective_integrity = Some(integ.into());
        self
    }

    /// `true` iff every field is `None`. Used by verifiers in strict mode
    /// to reject edges that claim economic semantics without attestation.
    pub fn is_empty(&self) -> bool {
        self.verifier_binary_hash.is_none()
            && self.wasmtime_version.is_none()
            && self.wasmtime_config_hash.is_none()
            && self.vrf_params_hash.is_none()
            && self.external_snapshot_root.is_none()
            && self.lean_spec_hash.is_none()
            && self.ifc_gated_effective_integrity.is_none()
    }
}

/// What kind of derivation this edge represents.
///
/// `Other(String)` is reserved for forward-compatible kinds that callers
/// can introduce without modifying this enum. The string value is shown
/// verbatim in lineage output.
///
/// # Economic-edge variants
///
/// The `Bid`, `Allocation`, `ContractEvaluation`, `Dispute`, and `MetricClaim`
/// variants are the substrate's economic primitives. They follow the same
/// signed-binding contract as `ToolCall` / `LlmCall`: payload fields shown
/// here are descriptive metadata, while the cryptographic binding to specific
/// values (bid amounts, allocation outcomes, metric values) happens via the
/// edge's `content_hash_hex` over a deterministic serialization of the
/// underlying record. Producers MUST set `content_hash_hex` for economic
/// edges; verifiers MUST treat absent `content_hash_hex` as unsigned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EdgeKind {
    /// A pod was admitted and given a SPIFFE identity.
    PodAdmit,
    /// A tool call was issued (Bash, Read, Write, …).
    ToolCall { tool: String },
    /// An LLM call was issued. `direction` is typically "prompt" or "response".
    LlmCall { provider: String, direction: String },
    /// Output of a tool/LLM call became an addressable artifact.
    ArtifactProduced,
    /// Two or more parents were merged into one child (e.g. a deterministic
    /// transform that consumed multiple inputs).
    Merge,
    /// A document was retrieved into the agent's context (web fetch, RAG index
    /// hit, local file, or memory recall). Captures the *provenance* of
    /// retrieved content so poisoned sources can be traced after the fact —
    /// the blind spot exploited by RAG/memory-poisoning attacks (AgentPoison,
    /// eTAMP) where injected documents silently steer later actions.
    DocumentRetrieved {
        /// Where the document came from (URL, index id, file path, memory key).
        source_url: String,
        /// Content hash of the retrieved bytes (hex), pinning exactly what was
        /// ingested so a later poisoning can be matched to this retrieval.
        content_hash: String,
        /// When the retrieval happened.
        retrieval_ts: DateTime<Utc>,
        /// Trust class of the source.
        source_class: SourceClass,
    },
    /// A bid submitted into a market mechanism. `market_id` identifies the
    /// auction; the bidder is the edge's first parent. The bid record
    /// (amount, side-attributes, sealed-or-open) is bound via `content_hash_hex`.
    Bid { market_id: String },
    /// An allocation produced by a market mechanism. `market_id` identifies
    /// the auction; `mechanism` names the rule ("vcg", "second_price",
    /// "posted_price", "gale_shapley", "double_auction"). Parents are the
    /// bid edges that fed into this allocation. The allocation record
    /// (winners, payments, integer-rounded micro-USD amounts) is bound via
    /// `content_hash_hex`.
    Allocation {
        market_id: String,
        mechanism: String,
    },
    /// One evaluation step of a programmable-contract state machine.
    /// `contract_id` identifies the contract; `step` is the monotonic step
    /// counter. The evaluated transition (input event, output obligations,
    /// payment flows, reputation effects) is bound via `content_hash_hex`.
    ContractEvaluation { contract_id: String, step: u32 },
    /// A dispute filed against a prior edge. `dispute_id` identifies the
    /// dispute; `target_edge_hash` is the hex SHA-256 of the disputed edge's
    /// canonical bytes. The claim record (evidence references, requested
    /// remedy) is bound via `content_hash_hex`.
    Dispute {
        dispute_id: String,
        target_edge_hash: String,
    },
    /// A signed welfare/economic-introspection metric claim over a specific
    /// window. `metric_name` identifies the metric (e.g. "producer_surplus",
    /// "gini", "time_to_clear"); `window_id` identifies the aggregation
    /// window. The metric value (with any differential-privacy noise
    /// parameters) is bound via `content_hash_hex`.
    MetricClaim {
        metric_name: String,
        window_id: String,
    },
    /// A settlement transaction on an external payment rail.
    /// `tx_ref` is the rail-side transaction id (Stripe `ch_…`, x402
    /// onchain tx hash, ACH trace number, …); `rail` names the
    /// settlement protocol ("stripe-connect", "x402-evm", "ach").
    /// Parents are the Allocation / ContractEvaluation edges that
    /// produced the obligation being settled. The payment record
    /// (amount, payee SPIFFE id, integer micro-USD) is bound via
    /// `content_hash_hex`.
    ///
    /// **Refund / chargeback semantics** (Close-to-Highest D4):
    /// a compensating refund is itself a `Settlement` edge whose
    /// `attrs["amount_micro_usd_signed"]` is *negative* (string-encoded
    /// `i64`) and whose `parents` include the original Settlement
    /// edge being reversed. The signed-sum of the two settlement
    /// edges over a charge is zero exactly when the refund is full.
    Settlement { tx_ref: String, rail: String },
    /// **Pigouvian P4.** An externality claim signed by a designated
    /// resource oracle. `resource` is the short stable tag from
    /// `nucleus_externality::ResourceDim::as_canonical_tag()` (e.g.
    /// "gpu_s", "co2_g"). `oracle_kid` is the signing-key id used to
    /// resolve the oracle's verifying key. The amount + freshness
    /// window + subject identity binding live in the
    /// `nucleus_externality::SignedExternalityClaim` whose
    /// canonical SHA-256 is bound via `content_hash_hex`. Parents
    /// chain back to the call edge the externality is attributed
    /// to.
    Externality {
        resource: String,
        oracle_kid: String,
    },
    /// **Pigouvian P5.** A rate-setter update to the Pigouvian λ_k
    /// for a given resource dimension, applicable over a clearing
    /// window. `resource` is the same short tag used by
    /// `Externality`; `rate_micro_usd_per_unit` is the marginal
    /// social cost per micro-unit of consumption, integer-only;
    /// `window_unix_micros` names the application window. The full
    /// rate record (full rate vector, cube slice the rate was
    /// derived from, signature) is bound via `content_hash_hex`.
    /// Rate updates are themselves signed edges so the rate timeline
    /// is auditable and replayable in the browser verifier.
    PigouvianRateUpdate {
        resource: String,
        rate_micro_usd_per_unit: u64,
        window_unix_micros: u64,
    },
    /// **Pigouvian P6.** A welfare-rebate disbursement to a witness-
    /// federation peer (or Pigouvian victim), funded from the VCG
    /// surplus collected through the Pigouvian re-weighting. Solves
    /// the classical VCG budget-balance gap: the federation peer
    /// who VERIFIED the externality claim gets paid proportional
    /// to their verification share. `recipient_kid` identifies the
    /// peer's signing key; `micro_usd` is the rebate amount (integer
    /// per ECON-PRECISION); `source_externality_edge_hash` is the
    /// content_hash_hex of the `Externality` edge that funded this
    /// rebate (used to enforce no-double-claim).
    WelfareRebate {
        recipient_kid: String,
        micro_usd: u64,
        source_externality_edge_hash: String,
    },
    /// Forward-compatible escape hatch. `name` is the caller-defined kind label.
    Other { name: String },
}

/// Trust class of a retrieved document's source. Drives downstream policy:
/// `Web` content is untrusted by default; `Memory`/`RagIndex` may be poisoned
/// across sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceClass {
    /// Fetched from the open web (untrusted).
    Web,
    /// Retrieved from a RAG / vector index.
    RagIndex,
    /// Read from a local file.
    LocalFile,
    /// Recalled from persistent agent memory (cross-session poisoning surface).
    Memory,
}

/// A single immutable lineage record.
///
/// Wire format is serde-compatible JSON for the JSONL sink and for cross-
/// process interchange. Field ordering follows audit-event convention:
/// `child` first, then `parents`, then metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageEdge {
    /// The derived identity this edge produced.
    pub child: CallSpiffeId,
    /// Source identities consumed to produce `child`. Most edges have one
    /// parent; merges have many. `PodAdmit` edges have zero.
    pub parents: Vec<CallSpiffeId>,
    /// Kind discriminator with kind-specific payload.
    #[serde(flatten)]
    pub kind: EdgeKind,
    /// Optional content hash of the derived value, in hex. When present this
    /// usually matches the `/sha256:…` suffix on `child`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash_hex: Option<String>,
    /// Wall-clock timestamp at edge emission time.
    pub ts: DateTime<Utc>,
    /// Free-form attributes (cost, model name, file path, exit code, …).
    /// Kept lexicographically sorted via BTreeMap for stable serialization.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attrs: BTreeMap<String, String>,
    /// Cryptographic proof signed over the edge's canonical bytes (see
    /// [`crate::proof::canonical_edge_bytes`]). `None` for legacy / unsigned
    /// edges. Edges produced by this crate's current emitters are unsigned;
    /// signing lands when an [`crate::IdentityFetcher`] impl gains an
    /// `sign_edge` method (PR-D). Verifiers should reject `None` in strict
    /// mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
    /// Pins the verification environment for this edge's claim (verifier
    /// binary, Wasmtime version + config, VRF parameters, external-snapshot
    /// root, Lean spec). `None` for legacy / structural-only edges. Economic
    /// edges (`Bid`, `Allocation`, `ContractEvaluation`, `Dispute`,
    /// `MetricClaim`) SHOULD populate the relevant fields when signed so
    /// that off-platform recomputation is genuinely closed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier_attestation: Option<VerifierAttestation>,
}

impl LineageEdge {
    /// Construct an edge from one parent.
    pub fn from_parent(child: CallSpiffeId, parent: CallSpiffeId, kind: EdgeKind) -> Self {
        Self {
            child,
            parents: vec![parent],
            kind,
            content_hash_hex: None,
            ts: Utc::now(),
            attrs: BTreeMap::new(),
            proof: None,
            verifier_attestation: None,
        }
    }

    /// Construct a document-retrieval edge: `child` retrieved a document from
    /// `source_url` (content hash `content_hash`, trust class `source_class`).
    /// `parent` is the retrieving identity (the pod/call doing the fetch).
    pub fn document_retrieved(
        child: CallSpiffeId,
        parent: CallSpiffeId,
        source_url: impl Into<String>,
        content_hash: impl Into<String>,
        source_class: SourceClass,
    ) -> Self {
        let content_hash = content_hash.into();
        Self {
            child,
            parents: vec![parent],
            kind: EdgeKind::DocumentRetrieved {
                source_url: source_url.into(),
                content_hash: content_hash.clone(),
                retrieval_ts: Utc::now(),
                source_class,
            },
            content_hash_hex: Some(content_hash),
            ts: Utc::now(),
            attrs: BTreeMap::new(),
            proof: None,
            verifier_attestation: None,
        }
    }

    /// Construct a pod-admission edge (no parents).
    pub fn pod_admit(pod: CallSpiffeId) -> Self {
        Self {
            child: pod,
            parents: Vec::new(),
            kind: EdgeKind::PodAdmit,
            content_hash_hex: None,
            ts: Utc::now(),
            attrs: BTreeMap::new(),
            proof: None,
            verifier_attestation: None,
        }
    }

    /// Builder: attach a content-hash to this edge.
    pub fn with_content_hash(mut self, hex: impl Into<String>) -> Self {
        self.content_hash_hex = Some(hex.into());
        self
    }

    /// Builder: attach a single attribute.
    pub fn with_attr(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attrs.insert(key.into(), value.into());
        self
    }

    /// Builder: attach a cryptographic proof.
    pub fn with_proof(mut self, proof: Proof) -> Self {
        self.proof = Some(proof);
        self
    }

    /// Builder: attach a verifier attestation pinning the recomputation
    /// environment for this edge's claim.
    pub fn with_verifier_attestation(mut self, va: VerifierAttestation) -> Self {
        self.verifier_attestation = Some(va);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::CallSpiffeId;

    fn pod() -> CallSpiffeId {
        CallSpiffeId::pod("prod.example.com", "agents", "coder").unwrap()
    }

    #[test]
    fn document_retrieved_round_trips_and_tags() {
        let p = pod();
        let child = p.derive_artifact(b"doc-bytes").unwrap();
        let edge = LineageEdge::document_retrieved(
            child,
            p,
            "https://docs.example.com/poisoned",
            "abc123",
            SourceClass::Web,
        );
        // Provenance fields are captured on the variant.
        match &edge.kind {
            EdgeKind::DocumentRetrieved {
                source_url,
                content_hash,
                source_class,
                ..
            } => {
                assert_eq!(source_url, "https://docs.example.com/poisoned");
                assert_eq!(content_hash, "abc123");
                assert_eq!(*source_class, SourceClass::Web);
            }
            other => panic!("expected DocumentRetrieved, got {other:?}"),
        }
        // serde round-trip via the JSONL wire format.
        let json = serde_json::to_string(&edge).unwrap();
        assert!(json.contains("\"kind\":\"document_retrieved\""));
        assert!(json.contains("\"source_class\":\"web\""));
        let back: LineageEdge = serde_json::from_str(&json).unwrap();
        assert_eq!(back, edge);
    }

    #[test]
    fn pod_admit_has_no_parents() {
        let p = pod();
        let edge = LineageEdge::pod_admit(p.clone());
        assert!(edge.parents.is_empty());
        assert_eq!(edge.child, p);
        assert!(matches!(edge.kind, EdgeKind::PodAdmit));
    }

    #[test]
    fn tool_call_edge_round_trips_json() {
        let p = pod();
        let child = p.derive_tool("Bash", Some(b"ls -la")).unwrap();
        let hash = child.content_hash_hex().unwrap().to_string();
        let edge = LineageEdge::from_parent(
            child,
            p,
            EdgeKind::ToolCall {
                tool: "Bash".to_string(),
            },
        )
        .with_content_hash(hash)
        .with_attr("cwd", "/tmp")
        .with_attr("exit_code", "0");

        let json = serde_json::to_string(&edge).unwrap();
        let back: LineageEdge = serde_json::from_str(&json).unwrap();
        assert_eq!(edge, back);
    }

    #[test]
    fn llm_call_edge_carries_provider_and_direction() {
        let p = pod();
        let prompt = p.derive_llm("anthropic", "prompt", b"hi").unwrap();
        let edge = LineageEdge::from_parent(
            prompt,
            p,
            EdgeKind::LlmCall {
                provider: "anthropic".to_string(),
                direction: "prompt".to_string(),
            },
        );
        let json = serde_json::to_string(&edge).unwrap();
        assert!(json.contains("\"kind\":\"llm_call\""));
        assert!(json.contains("\"provider\":\"anthropic\""));
        assert!(json.contains("\"direction\":\"prompt\""));
    }

    #[test]
    fn merge_edge_carries_multiple_parents() {
        let p = pod();
        let a = p.derive_tool("Read", Some(b"a")).unwrap();
        let b = p.derive_tool("Read", Some(b"b")).unwrap();
        let merged = p.derive_artifact(b"a+b").unwrap();
        let edge = LineageEdge {
            child: merged,
            parents: vec![a.clone(), b.clone()],
            kind: EdgeKind::Merge,
            content_hash_hex: None,
            ts: Utc::now(),
            attrs: BTreeMap::new(),
            proof: None,
            verifier_attestation: None,
        };
        assert_eq!(edge.parents.len(), 2);
        assert!(matches!(edge.kind, EdgeKind::Merge));
    }

    #[test]
    fn empty_attrs_skipped_in_json() {
        let p = pod();
        let edge = LineageEdge::pod_admit(p);
        let json = serde_json::to_string(&edge).unwrap();
        assert!(!json.contains("attrs"));
    }

    // ── Economic edge variant round-trips ───────────────────────────────
    // Each economic variant (Bid/Allocation/ContractEvaluation/Dispute/
    // MetricClaim) must round-trip through JSON identically and emit the
    // documented snake_case kind discriminator. The cryptographic binding
    // to specific values (amounts, payments, metric numbers) happens via
    // `content_hash_hex`, not via the kind payload — these tests only
    // verify wire-format stability.

    fn bid_child(p: &CallSpiffeId, market: &str) -> CallSpiffeId {
        p.derive_artifact(format!("bid:{market}").as_bytes())
            .unwrap()
    }

    #[test]
    fn bid_edge_round_trips() {
        let p = pod();
        let edge = LineageEdge::from_parent(
            bid_child(&p, "market-42"),
            p,
            EdgeKind::Bid {
                market_id: "market-42".to_string(),
            },
        )
        .with_content_hash("deadbeef".repeat(8));
        let json = serde_json::to_string(&edge).unwrap();
        assert!(json.contains("\"kind\":\"bid\""));
        assert!(json.contains("\"market_id\":\"market-42\""));
        let back: LineageEdge = serde_json::from_str(&json).unwrap();
        assert_eq!(edge, back);
    }

    #[test]
    fn allocation_edge_round_trips_with_mechanism() {
        let p = pod();
        let edge = LineageEdge::from_parent(
            p.derive_artifact(b"allocation").unwrap(),
            p,
            EdgeKind::Allocation {
                market_id: "market-42".to_string(),
                mechanism: "vcg".to_string(),
            },
        )
        .with_content_hash("c0ffee".repeat(10) + "1234");
        let json = serde_json::to_string(&edge).unwrap();
        assert!(json.contains("\"kind\":\"allocation\""));
        assert!(json.contains("\"mechanism\":\"vcg\""));
        let back: LineageEdge = serde_json::from_str(&json).unwrap();
        assert_eq!(edge, back);
    }

    #[test]
    fn contract_evaluation_edge_round_trips() {
        let p = pod();
        let edge = LineageEdge::from_parent(
            p.derive_artifact(b"contract-step-7").unwrap(),
            p,
            EdgeKind::ContractEvaluation {
                contract_id: "contract-abc".to_string(),
                step: 7,
            },
        );
        let json = serde_json::to_string(&edge).unwrap();
        assert!(json.contains("\"kind\":\"contract_evaluation\""));
        assert!(json.contains("\"step\":7"));
        let back: LineageEdge = serde_json::from_str(&json).unwrap();
        assert_eq!(edge, back);
    }

    #[test]
    fn dispute_edge_round_trips_with_target_hash() {
        let p = pod();
        let target_hash = "a".repeat(64);
        let edge = LineageEdge::from_parent(
            p.derive_artifact(b"dispute-claim").unwrap(),
            p,
            EdgeKind::Dispute {
                dispute_id: "dispute-1".to_string(),
                target_edge_hash: target_hash.clone(),
            },
        );
        let json = serde_json::to_string(&edge).unwrap();
        assert!(json.contains("\"kind\":\"dispute\""));
        assert!(json.contains(&target_hash));
        let back: LineageEdge = serde_json::from_str(&json).unwrap();
        assert_eq!(edge, back);
    }

    #[test]
    fn metric_claim_edge_round_trips() {
        let p = pod();
        let edge = LineageEdge::from_parent(
            p.derive_artifact(b"metric-window-2026-05").unwrap(),
            p,
            EdgeKind::MetricClaim {
                metric_name: "producer_surplus".to_string(),
                window_id: "2026-05".to_string(),
            },
        )
        .with_content_hash("b".repeat(64));
        let json = serde_json::to_string(&edge).unwrap();
        assert!(json.contains("\"kind\":\"metric_claim\""));
        assert!(json.contains("\"metric_name\":\"producer_surplus\""));
        let back: LineageEdge = serde_json::from_str(&json).unwrap();
        assert_eq!(edge, back);
    }

    // ── VerifierAttestation tests ──────────────────────────────────────

    #[test]
    fn verifier_attestation_round_trips() {
        let va = VerifierAttestation::new()
            .with_verifier_binary_hash("a".repeat(64))
            .with_wasmtime_version("44.0.0+nan_canon")
            .with_wasmtime_config_hash("b".repeat(64))
            .with_vrf_params_hash("c".repeat(64))
            .with_external_snapshot_root("d".repeat(64))
            .with_lean_spec_hash("e".repeat(64));
        assert!(!va.is_empty());
        let json = serde_json::to_string(&va).unwrap();
        let back: VerifierAttestation = serde_json::from_str(&json).unwrap();
        assert_eq!(va, back);
    }

    #[test]
    fn verifier_attestation_default_is_empty() {
        let va = VerifierAttestation::default();
        assert!(va.is_empty());
        let json = serde_json::to_string(&va).unwrap();
        // All fields skip-if-none → empty object
        assert_eq!(json, "{}");
    }

    #[test]
    fn edge_with_verifier_attestation_round_trips() {
        let p = pod();
        let va = VerifierAttestation::new()
            .with_lean_spec_hash("f".repeat(64))
            .with_verifier_binary_hash("9".repeat(64));
        let edge = LineageEdge::from_parent(
            p.derive_artifact(b"alloc").unwrap(),
            p,
            EdgeKind::Allocation {
                market_id: "m1".into(),
                mechanism: "vcg".into(),
            },
        )
        .with_content_hash("0".repeat(64))
        .with_verifier_attestation(va.clone());
        let json = serde_json::to_string(&edge).unwrap();
        assert!(json.contains("verifier_attestation"));
        assert!(json.contains("lean_spec_hash"));
        let back: LineageEdge = serde_json::from_str(&json).unwrap();
        assert_eq!(edge, back);
        assert_eq!(back.verifier_attestation, Some(va));
    }

    #[test]
    fn edge_without_attestation_skips_field_in_json() {
        let p = pod();
        let edge = LineageEdge::pod_admit(p);
        let json = serde_json::to_string(&edge).unwrap();
        assert!(!json.contains("verifier_attestation"));
    }

    #[test]
    fn canonical_bytes_differ_with_and_without_attestation() {
        use crate::proof::canonical_edge_bytes;
        let p = pod();
        let edge_bare = LineageEdge::from_parent(
            p.derive_artifact(b"x").unwrap(),
            p.clone(),
            EdgeKind::MetricClaim {
                metric_name: "gini".into(),
                window_id: "2026-05".into(),
            },
        )
        .with_content_hash("0".repeat(64));

        let va = VerifierAttestation::new().with_lean_spec_hash("a".repeat(64));
        let edge_attested = edge_bare.clone().with_verifier_attestation(va);

        let bytes_bare = canonical_edge_bytes(&edge_bare, None);
        let bytes_attested = canonical_edge_bytes(&edge_attested, None);
        assert_ne!(bytes_bare, bytes_attested);
    }

    #[test]
    fn canonical_bytes_differ_per_attestation_field() {
        use crate::proof::canonical_edge_bytes;
        let p = pod();
        let base = LineageEdge::from_parent(
            p.derive_artifact(b"x").unwrap(),
            p,
            EdgeKind::Dispute {
                dispute_id: "d1".into(),
                target_edge_hash: "0".repeat(64),
            },
        );

        let with_lean = base.clone().with_verifier_attestation(
            VerifierAttestation::new().with_lean_spec_hash("a".repeat(64)),
        );
        let with_vrf = base.clone().with_verifier_attestation(
            VerifierAttestation::new().with_vrf_params_hash("a".repeat(64)),
        );
        let with_both = base.clone().with_verifier_attestation(
            VerifierAttestation::new()
                .with_lean_spec_hash("a".repeat(64))
                .with_vrf_params_hash("a".repeat(64)),
        );

        let b_lean = canonical_edge_bytes(&with_lean, None);
        let b_vrf = canonical_edge_bytes(&with_vrf, None);
        let b_both = canonical_edge_bytes(&with_both, None);

        // Same hex value placed in different fields must produce different
        // canonical bytes (field positions are binding).
        assert_ne!(b_lean, b_vrf);
        // Two fields populated differs from either one alone.
        assert_ne!(b_lean, b_both);
        assert_ne!(b_vrf, b_both);
    }

    #[test]
    fn economic_kinds_have_distinct_canonical_tags() {
        // Reach into proof::canonical_edge_bytes via the public re-export to
        // confirm the discriminators wire up correctly. Each economic kind
        // must produce a distinct byte sequence purely from the kind tag,
        // even when child/parents/timestamp/content-hash are identical.
        use crate::proof::canonical_edge_bytes;

        let p = pod();
        let child = p.derive_artifact(b"x").unwrap();
        let ts = Utc::now();
        let mk = |k: EdgeKind| LineageEdge {
            child: child.clone(),
            parents: vec![p.clone()],
            kind: k,
            content_hash_hex: None,
            ts,
            attrs: BTreeMap::new(),
            proof: None,
            verifier_attestation: None,
        };

        let bid = canonical_edge_bytes(
            &mk(EdgeKind::Bid {
                market_id: "m".into(),
            }),
            None,
        );
        let alloc = canonical_edge_bytes(
            &mk(EdgeKind::Allocation {
                market_id: "m".into(),
                mechanism: "vcg".into(),
            }),
            None,
        );
        let ce = canonical_edge_bytes(
            &mk(EdgeKind::ContractEvaluation {
                contract_id: "c".into(),
                step: 0,
            }),
            None,
        );
        let disp = canonical_edge_bytes(
            &mk(EdgeKind::Dispute {
                dispute_id: "d".into(),
                target_edge_hash: "0".repeat(64),
            }),
            None,
        );
        let mc = canonical_edge_bytes(
            &mk(EdgeKind::MetricClaim {
                metric_name: "n".into(),
                window_id: "w".into(),
            }),
            None,
        );

        // All five must differ from each other and from existing kinds.
        let pod_admit = canonical_edge_bytes(&LineageEdge::pod_admit(p.clone()), None);
        let tool_call = canonical_edge_bytes(
            &mk(EdgeKind::ToolCall {
                tool: "Bash".into(),
            }),
            None,
        );

        for (i, a) in [&bid, &alloc, &ce, &disp, &mc].iter().enumerate() {
            for (j, b) in [&bid, &alloc, &ce, &disp, &mc].iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "economic kinds {i} and {j} share canonical bytes");
                }
            }
            assert_ne!(*a, &tool_call, "economic kind {i} collides with tool_call");
        }
        // pod_admit has no parents, so it differs structurally anyway.
        assert_ne!(bid, pod_admit);
    }

    // ── Pigouvian P4/P5/P6 variants ─────────────────────────────────────

    #[test]
    fn externality_edge_round_trips_json() {
        let p = pod();
        let child = p.derive_artifact(b"co2-claim-1").unwrap();
        let edge = LineageEdge::from_parent(
            child,
            p,
            EdgeKind::Externality {
                resource: "co2_g".to_string(),
                oracle_kid: "co2-oracle-key-1".to_string(),
            },
        )
        .with_content_hash("a".repeat(64))
        .with_attr("units_micro", "1500000");
        let json = serde_json::to_string(&edge).unwrap();
        let back: LineageEdge = serde_json::from_str(&json).unwrap();
        assert_eq!(edge, back);
        // Externally tagged: kind:"externality" appears verbatim.
        assert!(
            json.contains(r#""kind":"externality""#),
            "expected externally-tagged Externality, got {json}"
        );
    }

    #[test]
    fn pigouvian_rate_update_edge_round_trips_json() {
        let p = pod();
        let child = p.derive_artifact(b"rate-update-window-42").unwrap();
        let edge = LineageEdge::from_parent(
            child,
            p,
            EdgeKind::PigouvianRateUpdate {
                resource: "gpu_s".to_string(),
                rate_micro_usd_per_unit: 5,
                window_unix_micros: 1_700_000_000_000_000,
            },
        );
        let json = serde_json::to_string(&edge).unwrap();
        let back: LineageEdge = serde_json::from_str(&json).unwrap();
        assert_eq!(edge, back);
        assert!(json.contains(r#""kind":"pigouvian_rate_update""#));
    }

    #[test]
    fn welfare_rebate_edge_round_trips_json() {
        let p = pod();
        let child = p.derive_artifact(b"rebate-tx-1").unwrap();
        let edge = LineageEdge::from_parent(
            child,
            p,
            EdgeKind::WelfareRebate {
                recipient_kid: "witness-peer-1".to_string(),
                micro_usd: 1_250_000,
                source_externality_edge_hash: "f".repeat(64),
            },
        );
        let json = serde_json::to_string(&edge).unwrap();
        let back: LineageEdge = serde_json::from_str(&json).unwrap();
        assert_eq!(edge, back);
        assert!(json.contains(r#""kind":"welfare_rebate""#));
    }

    #[test]
    fn pigouvian_variants_have_distinct_kind_tags() {
        // kind_tag distinguishes the variants in canonical signing
        // bytes — a collision would let a hostile producer swap an
        // Externality claim for a WelfareRebate of the same shape.
        use crate::proof::canonical_edge_bytes;
        let p = pod();
        let ext = LineageEdge::from_parent(
            p.derive_artifact(b"ext").unwrap(),
            p.clone(),
            EdgeKind::Externality {
                resource: "gpu_s".to_string(),
                oracle_kid: "k1".to_string(),
            },
        );
        let rate = LineageEdge::from_parent(
            p.derive_artifact(b"rate").unwrap(),
            p.clone(),
            EdgeKind::PigouvianRateUpdate {
                resource: "gpu_s".to_string(),
                rate_micro_usd_per_unit: 5,
                window_unix_micros: 1_700_000_000_000_000,
            },
        );
        let rebate = LineageEdge::from_parent(
            p.derive_artifact(b"rebate").unwrap(),
            p,
            EdgeKind::WelfareRebate {
                recipient_kid: "w1".to_string(),
                micro_usd: 100,
                source_externality_edge_hash: "0".repeat(64),
            },
        );
        let bytes_ext = canonical_edge_bytes(&ext, None);
        let bytes_rate = canonical_edge_bytes(&rate, None);
        let bytes_rebate = canonical_edge_bytes(&rebate, None);
        assert_ne!(bytes_ext, bytes_rate);
        assert_ne!(bytes_ext, bytes_rebate);
        assert_ne!(bytes_rate, bytes_rebate);
    }
}
