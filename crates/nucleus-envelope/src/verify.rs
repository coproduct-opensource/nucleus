//! [`verify_bundle`] — re-validate a [`Bundle`] against its embedded
//! trust material, with no access to nucleus's running state.

use nucleus_lineage::{verify_chain, VerifyError};
use thiserror::Error;

use crate::bundle::{Bundle, ENVELOPE_SCHEMA_VERSION};

/// Errors returned by [`verify_bundle`].
#[derive(Debug, Error)]
pub enum VerifyBundleError {
    /// Envelope schema version is newer than this verifier understands.
    #[error("envelope schema version {got} > supported {supported}")]
    UnsupportedSchema { got: u32, supported: u32 },
    /// The session root SPIFFE id appears nowhere in the envelope's edges
    /// (every edge fails the under-root membership test).
    #[error("session root {root} matches no edges in envelope")]
    RootMismatch { root: String },
    /// At least one edge falls outside the session root.
    #[error(
        "edge #{index} child {child} is not under session root {root} — envelope must be \
         constrained to the session"
    )]
    EdgeOutsideRoot {
        index: usize,
        child: String,
        root: String,
    },
    /// Per-edge signature / chain verification failed.
    #[error("edge #{index} signature/chain verification failed: {source}")]
    Chain {
        index: usize,
        #[source]
        source: VerifyError,
    },
}

/// Result of a successful [`verify_bundle`] call.
///
/// Carries a few cheaply-extracted summary stats that downstream consumers
/// (UIs, regulators, audit reports) often want, so they don't have to
/// re-walk the envelope.
#[derive(Debug, Clone)]
pub struct VerificationReport {
    /// Number of edges in the verified envelope.
    pub edge_count: usize,
    /// Number of distinct issuer `kid`s observed in `proof` fields.
    pub distinct_issuers: usize,
    /// Number of signed tree heads attached to the envelope.
    pub checkpoint_count: usize,
}

/// Verify a [`Bundle`] standalone.
///
/// Performs:
///
/// 1. **Schema check** — refuses envelopes from a future schema version.
/// 2. **Membership** — every edge must fall under `envelope.session_root`
///    via the same structural rule as
///    [`crate::extract::extract_session_subgraph`].
/// 3. **Chain verification** — `nucleus_lineage::verify_chain` validates
///    every edge's signature and `prev_hash` linkage against the embedded
///    JWKS.
///
/// In v1 the embedded `SignedTreeHead`s are *time attestations* — their
/// signatures are NOT re-verified here because doing so requires an
/// out-of-band `TreeWitness` and audit paths binding session edges to the
/// signed root. Both arrive in v2. The chain proofs alone provide tamper
/// evidence for the envelope's edges.
pub fn verify_bundle(bundle: &Bundle) -> Result<VerificationReport, VerifyBundleError> {
    let env = &bundle.envelope;

    // 1) Schema.
    if env.meta.schema_version > ENVELOPE_SCHEMA_VERSION {
        return Err(VerifyBundleError::UnsupportedSchema {
            got: env.meta.schema_version,
            supported: ENVELOPE_SCHEMA_VERSION,
        });
    }

    // 2) Membership.
    let mut saw_root_edge = false;
    for (index, edge) in env.edges.iter().enumerate() {
        if !crate::extract::is_under_root(&edge.child, &env.session_root) {
            return Err(VerifyBundleError::EdgeOutsideRoot {
                index,
                child: edge.child.to_string(),
                root: env.session_root.to_string(),
            });
        }
        if edge.child == env.session_root {
            saw_root_edge = true;
        }
    }
    if !env.edges.is_empty() && !saw_root_edge {
        // Allow zero-edge envelopes (caller opted-in with `allow_empty`),
        // but a non-empty envelope must include the pod-admit edge.
        return Err(VerifyBundleError::RootMismatch {
            root: env.session_root.to_string(),
        });
    }

    // 3) Chain verification.
    verify_chain(&env.edges, &env.jwks)
        .map_err(|(index, source)| VerifyBundleError::Chain { index, source })?;

    let mut kids: Vec<&str> = env
        .edges
        .iter()
        .filter_map(|e| e.proof.as_ref().map(|p| p.kid.as_str()))
        .collect();
    kids.sort_unstable();
    kids.dedup();

    Ok(VerificationReport {
        edge_count: env.edges.len(),
        distinct_issuers: kids.len(),
        checkpoint_count: env.checkpoints.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{BundleBuilder, EnvelopeMeta};
    use nucleus_lineage::{CallSpiffeId, EdgeKind, InMemorySink, Jwks, LineageEdge, LineageSink};

    fn pod() -> CallSpiffeId {
        CallSpiffeId::pod("prod.example.com", "agents", "summarizer").unwrap()
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
        let err = verify_bundle(&bundle).unwrap_err();
        assert!(matches!(err, VerifyBundleError::UnsupportedSchema { .. }));
    }

    #[test]
    fn membership_rejects_foreign_edge() {
        let sink = InMemorySink::new();
        let mine = pod();
        let theirs = CallSpiffeId::pod("prod.example.com", "agents", "other").unwrap();
        sink.emit(LineageEdge::pod_admit(mine.clone())).unwrap();

        // Build a bundle for `mine`, then inject a foreign edge into the
        // envelope post-hoc.
        let mut bundle = BundleBuilder::new(mine)
            .payload(serde_json::json!({}))
            .sink(&sink)
            .jwks(Jwks { keys: vec![] })
            .build()
            .unwrap();
        bundle.envelope.edges.push(LineageEdge::from_parent(
            theirs.derive_tool("Read", Some(b"x")).unwrap(),
            theirs,
            EdgeKind::ToolCall {
                tool: "Read".to_string(),
            },
        ));

        let err = verify_bundle(&bundle).unwrap_err();
        assert!(matches!(err, VerifyBundleError::EdgeOutsideRoot { .. }));
    }

    #[test]
    fn unsigned_edges_fail_chain_verification() {
        let sink = InMemorySink::new();
        let p = pod();
        sink.emit(LineageEdge::pod_admit(p.clone())).unwrap();
        let bundle = BundleBuilder::new(p)
            .payload(serde_json::json!({}))
            .sink(&sink)
            .jwks(Jwks { keys: vec![] })
            .build()
            .unwrap();
        // The pod-admit edge has no proof (sink emits unsigned edges by
        // default in this test), so verify_chain must reject.
        let err = verify_bundle(&bundle).unwrap_err();
        assert!(matches!(err, VerifyBundleError::Chain { .. }));
    }
}
