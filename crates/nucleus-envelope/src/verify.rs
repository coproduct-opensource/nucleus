//! [`verify_bundle`] — re-validate a [`Bundle`] against a caller-supplied
//! [`TrustAnchor`].
//!
//! # Trust model (read this before using)
//!
//! The bundle's embedded `jwks` is **producer-controlled material**. An
//! attacker who fabricates a whole bundle generates their own keypair,
//! signs whatever edges they like, and ships the matching JWKS — every
//! signature, hash chain, and membership check passes against the
//! bundle's *own* claims.
//!
//! Therefore `verify_bundle` requires a [`TrustAnchor`] that names *which*
//! issuers the verifier trusts out-of-band:
//!
//! - [`TrustAnchor::from_jwks(trusted)`] — verifier supplies a JWKS they
//!   obtained through some authenticated side channel (file under
//!   `chmod 400`, OIDC discovery, signed bundle from operator). Edges
//!   must verify against this JWKS, not the one inside the bundle. The
//!   embedded JWKS is ignored.
//! - [`TrustAnchor::self_check_only()`] — explicit opt-in to "validate the
//!   envelope against the JWKS it carries." Proves the bundle is
//!   *internally consistent*; does NOT prove the producer is who they
//!   claim to be. The [`VerificationReport`] flags this mode so downstream
//!   code can refuse to treat it as a provenance claim.

use nucleus_lineage::{
    edge_content_hash, verify_chain, Ed25519Witness, InclusionProof, Jwks, LineageEdge, RootHash,
    VerifyError,
};
use sha2::Sha256;
use thiserror::Error;

use crate::bundle::{Bundle, ENVELOPE_SCHEMA_VERSION};

/// What the verifier trusts. See module docs for why this is required.
#[derive(Debug, Clone)]
pub struct TrustAnchor {
    jwks: Jwks,
    mode: TrustMode,
    /// Whether a bundle with zero edges is acceptable. Off by default —
    /// an empty envelope authenticates nothing yet a non-expert may read
    /// "ok" as a provenance claim. Opt-in only for callers that
    /// deliberately want "no-claim made" bundles (e.g. dry-run checks).
    allow_empty: bool,
    /// **v2 trust extension.** Ed25519 verifying-key bytes for the
    /// transparency-log witness that signed any
    /// [`crate::MerkleAnchor::sth`] on the bundle. When `None`, a
    /// bundle's Merkle anchor is left UNCHECKED and the verification
    /// report records `merkle_verified = false`. When `Some`, an
    /// envelope without a Merkle anchor still verifies (chain-only),
    /// but a present anchor MUST validate.
    witness_pubkey: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TrustMode {
    /// JWKS came from the caller out-of-band; embedded JWKS is ignored.
    OutOfBand,
    /// Caller explicitly opted into "use the JWKS in the bundle." The
    /// verifier still does the math, but the report carries
    /// `trust_mode = "self_check_only"` so downstream consumers know
    /// this is integrity-against-itself, not provenance.
    SelfCheckOnly,
}

impl TrustAnchor {
    /// Construct a trust anchor from a JWKS the verifier obtained
    /// out-of-band (file, OIDC discovery, signed operator bundle).
    /// This is the production path.
    pub fn from_jwks(jwks: Jwks) -> Self {
        Self {
            jwks,
            mode: TrustMode::OutOfBand,
            allow_empty: false,
            witness_pubkey: None,
        }
    }

    /// Explicit opt-in to validating an envelope against its own
    /// embedded JWKS. **Not a provenance claim** — only proves the
    /// bundle is internally consistent. Useful for offline audit of
    /// internal consistency, never for "is this from who they say."
    pub fn self_check_only() -> Self {
        Self {
            jwks: Jwks { keys: vec![] }, // unused; verify_bundle reads bundle.envelope.jwks
            mode: TrustMode::SelfCheckOnly,
            allow_empty: false,
            witness_pubkey: None,
        }
    }

    /// Permit bundles with zero envelope edges. Off by default — empty
    /// envelopes are forgeable nothings. See [`HIGH-4`] in audit log.
    pub fn allow_empty(mut self) -> Self {
        self.allow_empty = true;
        self
    }

    /// True if this anchor is opt-in self-check (not a provenance claim).
    pub fn is_self_check_only(&self) -> bool {
        self.mode == TrustMode::SelfCheckOnly
    }

    /// **v2 trust extension.** Attach the Ed25519 verifying-key bytes
    /// for the transparency-log witness whose STH the bundle's Merkle
    /// anchor was signed by. Callers obtain this key OUT-OF-BAND, the
    /// same as JWKS material.
    ///
    /// When set: a bundle with `merkle_anchor: Some(_)` MUST validate
    /// against this key (STH signature + per-edge inclusion proofs).
    /// When unset: a Merkle anchor present in the bundle is left
    /// unchecked; the report records `merkle_verified = false`.
    pub fn with_witness_pubkey(mut self, key_bytes: [u8; 32]) -> Self {
        self.witness_pubkey = Some(key_bytes);
        self
    }
}

/// Errors returned by [`verify_bundle`].
#[derive(Debug, Error)]
pub enum VerifyBundleError {
    /// Envelope schema version is newer than this verifier understands.
    #[error("envelope schema version {got} > supported {supported}")]
    UnsupportedSchema { got: u32, supported: u32 },
    /// Session root SPIFFE id is not a pod-shaped id (it carries a
    /// `/call/` suffix). A pod root has no call segments.
    #[error("session root {root} is not a pod-shaped SPIFFE id (must have no /call/ suffix)")]
    SessionRootNotPod { root: String },
    /// Envelope is empty and the trust anchor did not opt into accepting
    /// empty envelopes. Empty bundles authenticate nothing.
    #[error("envelope has zero edges; pass TrustAnchor::allow_empty() to accept")]
    EmptyEnvelope,
    /// First edge must be a pod-admit for the session root with no
    /// parents and no `prev_hash`.
    #[error(
        "edges[0] must be a PodAdmit edge for session root, with empty parents and no prev_hash; \
         got child={child} kind={kind}"
    )]
    BadHead { child: String, kind: String },
    /// At least one edge's child OR parents fall outside the session
    /// root. Membership is checked against both endpoints to catch
    /// merge edges that import foreign-trust-domain parents.
    #[error(
        "edge #{index} {endpoint} {id} is not under session root {root} — envelope must be \
         constrained to the session"
    )]
    OutsideRoot {
        index: usize,
        endpoint: &'static str,
        id: String,
        root: String,
    },
    /// Per-edge signature / chain verification failed against the trust
    /// anchor's JWKS.
    #[error("edge #{index} signature/chain verification failed: {source}")]
    Chain {
        index: usize,
        #[source]
        source: VerifyError,
    },
    /// Bundle carries a `merkle_anchor` but no `witness_pubkey` was
    /// supplied in the trust anchor.
    #[error(
        "bundle has a merkle_anchor but trust anchor has no witness_pubkey \
         (call TrustAnchor::with_witness_pubkey to verify it)"
    )]
    MissingWitnessKey,
    /// The witness signature on the Merkle anchor's STH did not verify.
    #[error("Merkle anchor STH signature verification failed: {0}")]
    MerkleAnchorBadSignature(String),
    /// Number of inclusion proofs doesn't match the number of envelope
    /// edges. The anchor commits to a specific edge ordering; any
    /// mismatch indicates tampering or builder bug.
    #[error("Merkle anchor has {got} inclusion proofs but envelope has {expected} edges")]
    MerkleAnchorLengthMismatch { got: usize, expected: usize },
    /// An inclusion proof failed to reconstruct the signed root from
    /// its leaf. `index` is the edge index in `envelope.edges`.
    #[error("edge #{index} inclusion proof failed against signed root: {detail}")]
    MerkleAnchorInclusionFailed { index: usize, detail: String },
}

/// Result of a successful [`verify_bundle`] call.
#[derive(Debug, Clone)]
pub struct VerificationReport {
    /// Number of edges in the verified envelope.
    pub edge_count: usize,
    /// Sorted, deduplicated list of issuer `kid`s observed in `proof`
    /// fields. Cross-reference these against your out-of-band trust
    /// directory.
    pub kids: Vec<String>,
    /// SPIFFE trust domain (URI authority) of the session root.
    pub trust_domain: String,
    /// SHA-256 of the canonical bytes of the last edge in the chain,
    /// hex-encoded. Pin this in your downstream system to detect bundle
    /// substitution — a different log produces a different head.
    pub head_edge_hash_hex: String,
    /// Number of signed tree heads attached to the envelope.
    pub checkpoint_count: usize,
    /// `true` if the caller chose [`TrustAnchor::self_check_only`] —
    /// the report attests *internal consistency*, not provenance.
    /// Downstream code MUST refuse to treat this as a provenance claim
    /// without further out-of-band evidence.
    pub trust_mode_self_check_only: bool,
    /// `true` if the bundle's `merkle_anchor` was present AND verified
    /// against the trust anchor's witness pubkey. Strongest claim a
    /// v2 bundle can produce — "this exact session is committed in
    /// the witness's log under a signed root."
    pub merkle_verified: bool,
}

/// Verify a [`Bundle`] against an explicit [`TrustAnchor`].
///
/// Performs (in order):
///
/// 1. **Schema check** — refuses envelopes from a future schema version.
/// 2. **Session-root shape** — root must be a pod-shaped SPIFFE id (no
///    `/call/` segment); otherwise the envelope's claimed "session"
///    semantic is nonsense.
/// 3. **Non-empty / empty opt-in** — empty bundles authenticate nothing,
///    so are rejected unless [`TrustAnchor::allow_empty`] was set.
/// 4. **Head edge** — `edges[0]` must be a pod-admit for `session_root`
///    with empty `parents` and (if signed) no `prev_hash`.
/// 5. **Membership** — every edge's `child` AND every `parent` must fall
///    under the session root via the same SPIFFE-URI prefix rule
///    [`crate::extract::is_under_root`] uses.
/// 6. **Trust-domain agreement** — every edge's child trust-domain must
///    match the session root's trust domain.
/// 7. **Chain verification** — `nucleus_lineage::verify_chain` validates
///    every edge's signature and `prev_hash` linkage against the *trust
///    anchor's* JWKS, NOT the JWKS embedded in the bundle (except in
///    explicit self-check-only mode).
///
/// STH signatures and Merkle inclusion proofs are not in v1; see crate
/// docs §"Scope limits."
pub fn verify_bundle(
    bundle: &Bundle,
    trust: &TrustAnchor,
) -> Result<VerificationReport, VerifyBundleError> {
    let env = &bundle.envelope;

    // 1) Schema.
    if env.meta.schema_version > ENVELOPE_SCHEMA_VERSION {
        return Err(VerifyBundleError::UnsupportedSchema {
            got: env.meta.schema_version,
            supported: ENVELOPE_SCHEMA_VERSION,
        });
    }

    // 2) Session root must be a pod (no /call/ segments). `is_call()` is
    // load-bearing here — a non-pod root would let an attacker claim a
    // tool-call SPIFFE id as the "session," which would prefix-match a
    // narrow subset of edges and mis-frame the envelope's scope.
    if env.session_root.is_call() {
        return Err(VerifyBundleError::SessionRootNotPod {
            root: env.session_root.to_string(),
        });
    }

    let trust_domain = spiffe_authority(env.session_root.as_str()).to_string();

    // 3) Empty envelopes authenticate nothing.
    if env.edges.is_empty() {
        if trust.allow_empty {
            return Ok(VerificationReport {
                edge_count: 0,
                kids: Vec::new(),
                trust_domain,
                head_edge_hash_hex: String::new(),
                checkpoint_count: env.checkpoints.len(),
                trust_mode_self_check_only: trust.is_self_check_only(),
                merkle_verified: false,
            });
        }
        return Err(VerifyBundleError::EmptyEnvelope);
    }

    // 4) Head edge must be pod-admit for session_root.
    let head = &env.edges[0];
    let head_ok = head.child == env.session_root
        && matches!(head.kind, nucleus_lineage::EdgeKind::PodAdmit)
        && head.parents.is_empty()
        && head
            .proof
            .as_ref()
            .map(|p| p.prev_hash.is_none())
            .unwrap_or(true);
    if !head_ok {
        return Err(VerifyBundleError::BadHead {
            child: head.child.to_string(),
            kind: format!("{:?}", head.kind),
        });
    }

    // 5) Membership: child AND every parent must be under the session
    // root. The parent check defends against a Merge edge whose child is
    // syntactically under root but whose parents reach into a foreign
    // pod's lineage.
    for (index, edge) in env.edges.iter().enumerate() {
        if !crate::extract::is_under_root(&edge.child, &env.session_root) {
            return Err(VerifyBundleError::OutsideRoot {
                index,
                endpoint: "child",
                id: edge.child.to_string(),
                root: env.session_root.to_string(),
            });
        }
        for parent in &edge.parents {
            if !crate::extract::is_under_root(parent, &env.session_root) {
                return Err(VerifyBundleError::OutsideRoot {
                    index,
                    endpoint: "parent",
                    id: parent.to_string(),
                    root: env.session_root.to_string(),
                });
            }
        }
    }

    // 6) Chain verification against the trust anchor's JWKS (or the
    // embedded one in explicit self-check mode).
    let verifying_jwks = match trust.mode {
        TrustMode::OutOfBand => &trust.jwks,
        TrustMode::SelfCheckOnly => &env.jwks,
    };
    verify_chain(&env.edges, verifying_jwks)
        .map_err(|(index, source)| VerifyBundleError::Chain { index, source })?;

    // 7) v2: Merkle anchor verification (binds session edges to a
    //    witness-signed root). Only attempted if the bundle carries
    //    an anchor; a bundle without one is a v1 bundle and is
    //    accepted at the chain-only level.
    //
    // Self-check mode SKIPS the anchor: self-check means "trust the
    // producer's own claim," and the Merkle anchor IS the producer's
    // claim. The producer can't validate the anchor against itself
    // without already trusting itself. Downstream verifiers with the
    // out-of-band witness pubkey are the ones who actually exercise
    // the anchor — and they must use `TrustAnchor::from_jwks(...)` +
    // `with_witness_pubkey(...)`.
    let merkle_verified = if trust.is_self_check_only() {
        false
    } else if let Some(anchor) = &env.merkle_anchor {
        verify_merkle_anchor(env.edges.as_slice(), anchor, trust)?;
        true
    } else {
        false
    };

    // 8) Report.
    let mut kids: Vec<String> = env
        .edges
        .iter()
        .filter_map(|e| e.proof.as_ref().map(|p| p.kid.clone()))
        .collect();
    kids.sort();
    kids.dedup();

    let head_edge_hash_hex = compute_head_edge_hash_hex(&env.edges);

    Ok(VerificationReport {
        edge_count: env.edges.len(),
        kids,
        trust_domain,
        head_edge_hash_hex,
        checkpoint_count: env.checkpoints.len(),
        trust_mode_self_check_only: trust.is_self_check_only(),
        merkle_verified,
    })
}

/// Verify the Merkle anchor: STH signature + each inclusion proof.
fn verify_merkle_anchor(
    edges: &[LineageEdge],
    anchor: &crate::bundle::MerkleAnchor,
    trust: &TrustAnchor,
) -> Result<(), VerifyBundleError> {
    // Caller must supply the witness pubkey out-of-band — same trust
    // discipline as the JWKS. The bundle's *anchor* is producer-
    // controlled, so without an OOB witness key the anchor is just
    // self-claim, not provenance.
    let witness_bytes = trust
        .witness_pubkey
        .ok_or(VerifyBundleError::MissingWitnessKey)?;
    let witness = Ed25519Witness::verify_only(witness_bytes)
        .map_err(|e| VerifyBundleError::MerkleAnchorBadSignature(e.to_string()))?;
    anchor
        .sth
        .verify(&witness)
        .map_err(|e| VerifyBundleError::MerkleAnchorBadSignature(e.to_string()))?;

    if anchor.inclusion_proofs.len() != edges.len() {
        return Err(VerifyBundleError::MerkleAnchorLengthMismatch {
            got: anchor.inclusion_proofs.len(),
            expected: edges.len(),
        });
    }

    // Reconstruct the signed RootHash for ct-merkle verification.
    let root_bytes_vec = hex::decode(&anchor.sth.root_hash_hex).map_err(|e| {
        VerifyBundleError::MerkleAnchorBadSignature(format!("malformed root_hash_hex: {e}"))
    })?;
    if root_bytes_vec.len() != 32 {
        return Err(VerifyBundleError::MerkleAnchorBadSignature(
            "root_hash_hex must be exactly 32 bytes".into(),
        ));
    }
    let mut root_arr = [0u8; 32];
    root_arr.copy_from_slice(&root_bytes_vec);
    // `digest::Output<Sha256>` is `hybrid_array::Array<u8, U32>` in
    // digest 0.11 (the version ct-merkle 0.3 uses). The `From<[u8; 32]>`
    // impl gives us the conversion.
    let digest_output: sha2::digest::Output<Sha256> = root_arr.into();
    let root: RootHash<Sha256> = RootHash::new(digest_output, anchor.sth.tree_size);

    for (index, (edge, inc)) in edges.iter().zip(&anchor.inclusion_proofs).enumerate() {
        // The leaves the MerkleSink committed to are the edges'
        // canonical content hashes with `prev_hash = None` — pinning
        // this here matches the producer-side `MerkleSink::emit` leaf
        // encoding at crates/nucleus-lineage/src/merkle.rs.
        let leaf_hash = edge_content_hash(edge, None);
        let leaf_bytes: Vec<u8> = leaf_hash.to_vec();
        let path_bytes = hex::decode(&inc.audit_path_hex).map_err(|e| {
            VerifyBundleError::MerkleAnchorInclusionFailed {
                index,
                detail: format!("audit_path_hex decode: {e}"),
            }
        })?;
        let proof: InclusionProof<Sha256> =
            InclusionProof::try_from_bytes(path_bytes).map_err(|e| {
                VerifyBundleError::MerkleAnchorInclusionFailed {
                    index,
                    detail: format!("audit_path malformed: {e:?}"),
                }
            })?;
        root.verify_inclusion(&leaf_bytes, inc.leaf_index, &proof)
            .map_err(|e| VerifyBundleError::MerkleAnchorInclusionFailed {
                index,
                detail: format!("ct-merkle: {e:?}"),
            })?;
    }
    Ok(())
}

/// Walk the chain to compute the hash of the head (last) edge so it can
/// be reported / pinned. Uses the same `prev_hash` chaining the
/// signatures cover, so the head hash is a stable function of the chain
/// content.
fn compute_head_edge_hash_hex(edges: &[LineageEdge]) -> String {
    let mut prev: Option<[u8; 32]> = None;
    let mut last: [u8; 32] = [0u8; 32];
    for edge in edges {
        let h = nucleus_lineage::edge_content_hash(edge, prev.as_ref());
        last = h;
        prev = Some(h);
    }
    hex::encode(last)
}

fn spiffe_authority(s: &str) -> &str {
    s.strip_prefix("spiffe://")
        .and_then(|rest| rest.split_once('/').map(|(auth, _)| auth))
        .unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{BundleBuilder, EnvelopeMeta};
    use nucleus_lineage::{CallSpiffeId, EdgeKind, InMemorySink, Jwks, LineageEdge, LineageSink};

    fn pod() -> CallSpiffeId {
        CallSpiffeId::pod("prod.example.com", "agents", "summarizer").unwrap()
    }

    fn empty_anchor() -> TrustAnchor {
        TrustAnchor::from_jwks(Jwks { keys: vec![] })
    }

    #[test]
    fn schema_check_rejects_future_version() {
        let sink = InMemorySink::new();
        let p = pod();
        sink.emit(LineageEdge::pod_admit(p.clone())).unwrap();
        let mut bundle = BundleBuilder::new(p)
            .payload(serde_json::json!({}))
            .sink(&sink)
            .jwks(Jwks { keys: vec![] })
            .build()
            .unwrap();
        bundle.envelope.meta = EnvelopeMeta {
            schema_version: ENVELOPE_SCHEMA_VERSION + 1,
            created_at: bundle.envelope.meta.created_at,
        };
        let err = verify_bundle(&bundle, &empty_anchor()).unwrap_err();
        assert!(matches!(err, VerifyBundleError::UnsupportedSchema { .. }));
    }

    #[test]
    fn rejects_non_pod_session_root() {
        // Build a bundle, then mutate session_root to a non-pod id.
        let sink = InMemorySink::new();
        let p = pod();
        sink.emit(LineageEdge::pod_admit(p.clone())).unwrap();
        let mut bundle = BundleBuilder::new(p.clone())
            .payload(serde_json::json!({}))
            .sink(&sink)
            .jwks(Jwks { keys: vec![] })
            .build()
            .unwrap();
        bundle.envelope.session_root = p.derive_tool("Read", None).unwrap();
        let err = verify_bundle(&bundle, &empty_anchor()).unwrap_err();
        assert!(matches!(err, VerifyBundleError::SessionRootNotPod { .. }));
    }

    #[test]
    fn rejects_empty_envelope_by_default() {
        let sink = InMemorySink::new();
        let bundle = BundleBuilder::new(pod())
            .payload(serde_json::json!({}))
            .sink(&sink)
            .jwks(Jwks { keys: vec![] })
            .allow_empty()
            .build()
            .unwrap();
        let err = verify_bundle(&bundle, &empty_anchor()).unwrap_err();
        assert!(matches!(err, VerifyBundleError::EmptyEnvelope));
    }

    #[test]
    fn accepts_empty_envelope_with_allow_empty_opt_in() {
        let sink = InMemorySink::new();
        let bundle = BundleBuilder::new(pod())
            .payload(serde_json::json!({}))
            .sink(&sink)
            .jwks(Jwks { keys: vec![] })
            .allow_empty()
            .build()
            .unwrap();
        let report = verify_bundle(&bundle, &empty_anchor().allow_empty()).unwrap();
        assert_eq!(report.edge_count, 0);
        assert!(report.head_edge_hash_hex.is_empty());
    }

    #[test]
    fn rejects_head_edge_not_pod_admit() {
        let sink = InMemorySink::new();
        let p = pod();
        // Skip pod-admit; first edge is a tool call.
        sink.emit(LineageEdge::from_parent(
            p.derive_tool("Read", Some(b"x")).unwrap(),
            p.clone(),
            EdgeKind::ToolCall {
                tool: "Read".to_string(),
            },
        ))
        .unwrap();
        let bundle = BundleBuilder::new(p)
            .payload(serde_json::json!({}))
            .sink(&sink)
            .jwks(Jwks { keys: vec![] })
            .build()
            .unwrap();
        let err = verify_bundle(&bundle, &empty_anchor()).unwrap_err();
        assert!(matches!(err, VerifyBundleError::BadHead { .. }));
    }

    #[test]
    fn rejects_foreign_parent_via_merge() {
        // Construct a Merge edge whose child is under our root but whose
        // parents include a foreign-pod id. Tighter membership check must
        // catch this.
        let sink = InMemorySink::new();
        let mine = pod();
        let theirs = CallSpiffeId::pod("attacker.example.com", "evil", "evil-sa").unwrap();
        sink.emit(LineageEdge::pod_admit(mine.clone())).unwrap();
        let local_tool = mine.derive_tool("Read", Some(b"a")).unwrap();
        sink.emit(LineageEdge::from_parent(
            local_tool.clone(),
            mine.clone(),
            EdgeKind::ToolCall {
                tool: "Read".to_string(),
            },
        ))
        .unwrap();
        let attacker_tool = theirs.derive_tool("Read", Some(b"b")).unwrap();
        let merged = mine.derive_artifact(b"merged").unwrap();
        // Hand-craft the merge edge with a foreign parent.
        let bad_merge = LineageEdge {
            child: merged,
            parents: vec![local_tool, attacker_tool],
            kind: EdgeKind::Merge,
            content_hash_hex: None,
            ts: chrono::Utc::now(),
            attrs: Default::default(),
            proof: None,
        };
        sink.emit(bad_merge).unwrap();

        let bundle = BundleBuilder::new(mine)
            .payload(serde_json::json!({}))
            .sink(&sink)
            .jwks(Jwks { keys: vec![] })
            .build()
            .unwrap();
        let err = verify_bundle(&bundle, &empty_anchor()).unwrap_err();
        assert!(
            matches!(
                err,
                VerifyBundleError::OutsideRoot {
                    endpoint: "parent",
                    ..
                }
            ),
            "expected parent OutsideRoot, got {err:?}"
        );
    }

    #[test]
    fn self_check_only_flag_surfaces_in_report() {
        // Bundle with no signed edges, verified in self-check mode with
        // allow_empty — confirms the mode flag flows through to the report.
        let sink = InMemorySink::new();
        let bundle = BundleBuilder::new(pod())
            .payload(serde_json::json!({}))
            .sink(&sink)
            .jwks(Jwks { keys: vec![] })
            .allow_empty()
            .build()
            .unwrap();
        let report = verify_bundle(&bundle, &TrustAnchor::self_check_only().allow_empty()).unwrap();
        assert!(report.trust_mode_self_check_only);
    }
}
