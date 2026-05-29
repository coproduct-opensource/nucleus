//! [`SessionWriter`] — emit hash-chained, signed lineage edges for a
//! session without making every caller re-implement the chain bookkeeping.
//!
//! Wraps a [`LineageSink`] + [`EdgeSigner`] and maintains the running
//! `prev_hash` internally. Callers hand it bare [`LineageEdge`]s; the
//! writer signs them in chain order.

use std::sync::Mutex;

use nucleus_lineage::{
    canonical_edge_bytes, edge_content_hash, EdgeSigner, IssuerError, LineageEdge, LineageSink,
    Proof, SinkError,
};
use thiserror::Error;

/// Errors raised while emitting through a [`SessionWriter`].
#[derive(Debug, Error)]
pub enum SessionWriterError {
    /// Signing failed (issuer backend error).
    #[error("issuer signing failure: {0}")]
    Signing(#[from] IssuerError),
    /// Persisting to the underlying sink failed.
    #[error("sink error: {0}")]
    Sink(#[from] SinkError),
    /// Internal chain-state mutex was poisoned by a previous panic.
    #[error("session writer state lock poisoned")]
    Poisoned,
}

/// Single-session edge emitter.
///
/// Concurrency: `emit_signed` is `&self` and takes the internal mutex,
/// so the writer is `Send + Sync`. Hash-chain order is enforced by the
/// order calls reach the mutex — under concurrent emit, callers must
/// serialize externally if they need a deterministic order.
pub struct SessionWriter<'a> {
    sink: &'a dyn LineageSink,
    issuer: &'a dyn EdgeSigner,
    state: Mutex<ChainState>,
}

struct ChainState {
    prev_hash: Option<[u8; 32]>,
}

impl<'a> SessionWriter<'a> {
    /// Wrap a sink and signer. The chain starts fresh — the writer does
    /// NOT replay existing edges in the sink. Callers re-opening a
    /// persistent session need to pre-seed via [`Self::with_prev_hash`].
    pub fn new(sink: &'a dyn LineageSink, issuer: &'a dyn EdgeSigner) -> Self {
        Self {
            sink,
            issuer,
            state: Mutex::new(ChainState { prev_hash: None }),
        }
    }

    /// Construct with a pre-seeded `prev_hash` from a prior session's
    /// last edge. Use when continuing an existing chain.
    pub fn with_prev_hash(
        sink: &'a dyn LineageSink,
        issuer: &'a dyn EdgeSigner,
        prev_hash: [u8; 32],
    ) -> Self {
        Self {
            sink,
            issuer,
            state: Mutex::new(ChainState {
                prev_hash: Some(prev_hash),
            }),
        }
    }

    /// Sign `edge` against the current `prev_hash`, attach the resulting
    /// [`Proof`], persist via the sink, and advance the chain. Returns
    /// the canonical hash of the emitted edge so callers can correlate.
    pub fn emit_signed(&self, edge: LineageEdge) -> Result<[u8; 32], SessionWriterError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| SessionWriterError::Poisoned)?;
        let prev = state.prev_hash;
        let bytes = canonical_edge_bytes(&edge, prev.as_ref());
        let sig = self.issuer.sign(&bytes)?;
        let mut proof = Proof::new(self.issuer.kid(), self.issuer.alg(), sig);
        if let Some(h) = prev {
            proof = proof.with_prev_hash(h);
        }
        let signed = edge.with_proof(proof);
        let new_hash = edge_content_hash(&signed, prev.as_ref());
        self.sink.emit(signed)?;
        state.prev_hash = Some(new_hash);
        Ok(new_hash)
    }

    /// Current head hash (the hash of the last edge emitted, or `None`
    /// if no edges have been emitted yet).
    pub fn head(&self) -> Result<Option<[u8; 32]>, SessionWriterError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| SessionWriterError::Poisoned)?
            .prev_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nucleus_lineage::{
        verify_chain, CallSpiffeId, EdgeKind, InMemorySink, Jwks, LineageEdge, LocalIssuer,
    };

    fn pod() -> CallSpiffeId {
        CallSpiffeId::pod("prod.example.com", "agents", "summarizer").unwrap()
    }

    #[test]
    fn writer_signs_and_chains_three_edges() {
        let sink = InMemorySink::new();
        let issuer = LocalIssuer::random().unwrap();
        let writer = SessionWriter::new(&sink, &issuer);
        let p = pod();

        writer
            .emit_signed(LineageEdge::pod_admit(p.clone()))
            .unwrap();
        let tool = p.derive_tool("Read", Some(b"x")).unwrap();
        writer
            .emit_signed(LineageEdge::from_parent(
                tool.clone(),
                p,
                EdgeKind::ToolCall {
                    tool: "Read".to_string(),
                },
            ))
            .unwrap();
        let leaf = tool.derive_artifact(b"y").unwrap();
        writer
            .emit_signed(LineageEdge::from_parent(
                leaf,
                tool,
                EdgeKind::ArtifactProduced,
            ))
            .unwrap();

        // The chain should verify end-to-end.
        let edges = sink.iter().unwrap();
        assert_eq!(edges.len(), 3);
        let jwks: Jwks = serde_json::from_value(issuer.publish_jwks()).unwrap();
        verify_chain(&edges, &jwks).expect("3-edge signed chain should verify");
    }

    #[test]
    fn head_advances_after_each_emit() {
        let sink = InMemorySink::new();
        let issuer = LocalIssuer::random().unwrap();
        let writer = SessionWriter::new(&sink, &issuer);
        assert_eq!(writer.head().unwrap(), None);

        writer.emit_signed(LineageEdge::pod_admit(pod())).unwrap();
        let h1 = writer.head().unwrap();
        assert!(h1.is_some());
    }
}
